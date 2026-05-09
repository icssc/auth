import { decodeIdToken } from "arctic";
import { Hono } from "hono";
import { validateClient } from "@/lib/clients";
import { createAppleClient } from "@/lib/oauth";
import type { AuthCode } from "@/lib/schemas/authcode";
import { StateDataSchema } from "@/lib/schemas/state";
import { tryCatch, tryCatchSync } from "@/lib/try-catch";
import { base64ToArrayBuffer, hmacFromSecret } from "@/lib/verify-state";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.post("/", async (c) => {
    const body = await c.req.parseBody();
    const code = body.code as string | undefined;
    const stateParam = body.state as string | undefined;
    const userParam = body.user as string | undefined;
    const errorParam = body.error as string | undefined;

    if (errorParam) {
        return c.json(
            { error: "apple_oauth_error", description: errorParam },
            400
        );
    }

    if (!code || !stateParam) {
        return c.json({ error: "invalid_request" }, 400);
    }

    const decodeResult = tryCatchSync(() => JSON.parse(atob(stateParam)));
    if (decodeResult.error) {
        return c.json({ error: "invalid_state" }, 400);
    }
    const parsedStateData = StateDataSchema.safeParse(decodeResult.data);
    if (!parsedStateData.success) {
        return c.json({ error: "invalid_state" }, 400);
    }

    const { digest: stateDataDigest, inner: stateData } = parsedStateData.data;

    if (stateData.provider !== "apple") {
        return c.json({ error: "invalid_state" }, 400);
    }

    const signatureResult = tryCatchSync(() =>
        base64ToArrayBuffer(stateDataDigest)
    );
    if (signatureResult.error) {
        return c.json({ error: "invalid_state" }, 400);
    }
    const verifyResult = await tryCatch(
        crypto.subtle.verify(
            "HMAC",
            await hmacFromSecret(c.env.GOOGLE_CLIENT_SECRET),
            signatureResult.data,
            new TextEncoder().encode(JSON.stringify(stateData))
        )
    );

    if (!verifyResult.data) {
        return c.json({ error: "invalid_state" }, 400);
    }

    const client = validateClient(stateData.client_id, stateData.redirect_uri);
    if (!client) {
        return c.json({ error: "unauthorized_client" }, 400);
    }

    const apple = createAppleClient(c.env);
    const { data: tokens, error: tokenError } = await tryCatch(
        apple.validateAuthorizationCode(code)
    );
    if (tokenError || !tokens) {
        return c.json({ error: "apple_token_exchange_failed" }, 500);
    }

    const claims = decodeIdToken(tokens.idToken()) as {
        sub: string;
        email: string;
    };

    const userId = `apple_${claims.sub}`;

    let userName = claims.email;
    let userEmail = claims.email;

    if (userParam) {
        const userResult = tryCatchSync(() => JSON.parse(userParam));
        if (!userResult.error && userResult.data) {
            const appleUser = userResult.data as {
                name?: { firstName?: string; lastName?: string };
                email?: string;
            };
            if (appleUser.name) {
                const parts = [
                    appleUser.name.firstName,
                    appleUser.name.lastName,
                ].filter(Boolean);
                if (parts.length > 0) {
                    userName = parts.join(" ");
                }
            }
            if (appleUser.email) {
                userEmail = appleUser.email;
            }
        }
    }

    const profileKey = `apple_profile:${claims.sub}`;
    const existingProfile = await c.env.AUTH_KV_USERS.get(profileKey);

    if (userParam || !existingProfile) {
        await c.env.AUTH_KV_USERS.put(
            profileKey,
            JSON.stringify({ name: userName, email: userEmail })
        );
    } else {
        const profile = JSON.parse(existingProfile) as {
            name: string;
            email: string;
        };
        userName = profile.name;
        userEmail = profile.email;
    }

    const sessionId = crypto.randomUUID();
    const sessionData = {
        user_id: userId,
        email: userEmail,
        name: userName,
        provider: "apple",
        scope: stateData.scope,
    };
    const sessionTtl =
        Number.parseInt(c.env.SESSION_TTL_SECONDS.toString(), 10) || 86400;

    await c.env.AUTH_KV_SESSIONS.put(sessionId, JSON.stringify(sessionData), {
        expirationTtl: sessionTtl,
    });

    const authCode = crypto.randomUUID();
    const codeData: AuthCode = {
        provider: "apple",
        user_id: userId,
        email: userEmail,
        name: userName,
        client_id: stateData.client_id,
        redirect_uri: stateData.redirect_uri,
        code_challenge: stateData.code_challenge,
        scope: stateData.scope,
        created_at: Date.now(),
    };

    await c.env.AUTH_KV_AUTHCODES.put(authCode, JSON.stringify(codeData), {
        expirationTtl:
            Number.parseInt(c.env.CODE_TTL_SECONDS.toString(), 10) || 300,
    });

    const redirectUrl = new URL(stateData.redirect_uri);
    redirectUrl.searchParams.set("code", authCode);
    if (stateData.state) {
        redirectUrl.searchParams.set("state", stateData.state);
    }

    const requestUrl = new URL(c.req.url);
    const cookieDomain = requestUrl.hostname;
    const isSecure = requestUrl.protocol === "https:";

    const cookieValue = isSecure
        ? `sid=${sessionId}; Domain=${cookieDomain}; HttpOnly; Secure; SameSite=None; Max-Age=${sessionTtl}; Path=/`
        : `sid=${sessionId}; HttpOnly; SameSite=Lax; Max-Age=${sessionTtl}; Path=/`;

    const response = c.redirect(redirectUrl.toString(), 302);
    response.headers.set("Set-Cookie", cookieValue);
    return response;
});

export default app;
