import { decodeIdToken } from "arctic";
import { Hono } from "hono";
import { validateClient } from "@/lib/clients";
import { createGoogleClient } from "@/lib/oauth";
import type { AuthCode } from "@/lib/schemas/authcode";
import { StateDataSchema } from "@/lib/schemas/state";
import { tryCatch, tryCatchSync } from "@/lib/try-catch";
import { base64ToArrayBuffer, hmacFromSecret } from "@/lib/verify-state";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.get("/", async (c) => {
    const { code, state: stateParam, error } = c.req.query();

    if (error) {
        return c.json({ error: "google_oauth_error", description: error }, 400);
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

    if (stateData.provider !== "google") {
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
            new TextEncoder().encode(JSON.stringify(decodeResult.data.inner))
        )
    );

    // the presence of an error implies data === null
    if (!verifyResult.data) {
        return c.json({ error: "invalid_state" }, 400);
    }

    const client = validateClient(stateData.client_id, stateData.redirect_uri);
    if (!client) {
        return c.json({ error: "unauthorized_client" }, 400);
    }

    const google = createGoogleClient(c.env);
    const { data: tokens, error: tokenError } = await tryCatch(
        google.validateAuthorizationCode(code, stateData.code_verifier)
    );
    if (tokenError || !tokens) {
        return c.json({ error: "google_token_exchange_failed" }, 500);
    }

    const googleAccessToken = tokens.accessToken();
    const googleTokenExpiry = tokens.accessTokenExpiresAt()?.getTime();

    const googleRefreshToken = tokens.hasRefreshToken()
        ? tokens.refreshToken()
        : undefined;

    const claims = decodeIdToken(tokens.idToken()) as {
        sub: string;
        email: string;
        name: string;
        picture: string;
    };

    const userId = `google_${claims.sub}`;

    const sessionId = crypto.randomUUID();
    const sessionData = {
        user_id: userId,
        email: claims.email,
        name: claims.name,
        picture: claims.picture,
        provider: "google" as const,
        google_access_token: googleAccessToken,
        google_refresh_token: googleRefreshToken,
        google_token_expiry: googleTokenExpiry,
        scope: stateData.scope,
    };
    const sessionTtl =
        Number.parseInt(c.env.SESSION_TTL_SECONDS.toString(), 10) || 86400;

    await c.env.AUTH_KV_SESSIONS.put(sessionId, JSON.stringify(sessionData), {
        expirationTtl: sessionTtl,
    });

    const authCode = crypto.randomUUID();
    const codeData = {
        provider: "google" as const,
        user_id: userId,
        email: claims.email,
        name: claims.name,
        picture: claims.picture,
        client_id: stateData.client_id,
        redirect_uri: stateData.redirect_uri,
        code_challenge: stateData.code_challenge,
        scope: stateData.scope,
        created_at: Date.now(),
        google_access_token: googleAccessToken,
        google_refresh_token: googleRefreshToken,
        google_token_expiry: googleTokenExpiry,
    } satisfies AuthCode;

    await c.env.AUTH_KV_AUTHCODES.put(authCode, JSON.stringify(codeData), {
        expirationTtl:
            Number.parseInt(c.env.CODE_TTL_SECONDS.toString(), 10) || 300,
    });

    const redirectUrl = new URL(stateData.redirect_uri);
    redirectUrl.searchParams.set("code", authCode);
    if (stateData.state) redirectUrl.searchParams.set("state", stateData.state);

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
