import { decodeIdToken } from "arctic";
import { Hono } from "hono";
import {
    finalizeBrowserOAuthLogin,
    verifyOAuthCallbackState,
} from "@/lib/auth/oauth-callback";
import { createAppleClient } from "@/lib/oauth";
import type { AuthCode } from "@/lib/schemas/authcode";
import { tryCatch, tryCatchSync } from "@/lib/try-catch";

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

    const stateResult = await verifyOAuthCallbackState(
        stateParam,
        "apple",
        c.env.STATE_SIGNING_SECRET
    );
    if (!stateResult.ok) {
        return c.json({ error: stateResult.error }, 400);
    }

    const stateData = stateResult.state;

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

    const sessionData = {
        user_id: userId,
        email: userEmail,
        name: userName,
        provider: "apple" as const,
        scope: stateData.scope,
    };
    const sessionTtl =
        Number.parseInt(c.env.SESSION_TTL_SECONDS.toString(), 10) || 86400;
    const codeTtl =
        Number.parseInt(c.env.CODE_TTL_SECONDS.toString(), 10) || 300;

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

    const { location, setCookie } = await finalizeBrowserOAuthLogin({
        kvSessions: c.env.AUTH_KV_SESSIONS,
        kvAuthCodes: c.env.AUTH_KV_AUTHCODES,
        sessionTtlSeconds: sessionTtl,
        codeTtlSeconds: codeTtl,
        sessionData,
        authCode: codeData,
        redirectUri: stateData.redirect_uri,
        clientState: stateData.state,
        requestUrl: new URL(c.req.url),
    });

    const response = c.redirect(location, 302);
    response.headers.set("Set-Cookie", setCookie);
    return response;
});

export default app;
