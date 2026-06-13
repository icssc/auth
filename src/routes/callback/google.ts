import { decodeIdToken } from "arctic";
import { Hono } from "hono";
import {
    finalizeBrowserOAuthLogin,
    verifyOAuthCallbackState,
} from "@/lib/auth/oauth-callback";
import { createGoogleClient } from "@/lib/oauth";
import type { AuthCode } from "@/lib/schemas/authcode";
import type { Session } from "@/lib/schemas/session";
import { tryCatch } from "@/lib/try-catch";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.get("/", async (c) => {
    const { code, state: stateParam, error } = c.req.query();

    if (error) {
        return c.json({ error: "google_oauth_error", description: error }, 400);
    }

    if (!code || !stateParam) {
        return c.json({ error: "invalid_request" }, 400);
    }

    const stateResult = await verifyOAuthCallbackState(
        stateParam,
        "google",
        c.env.STATE_SIGNING_SECRET
    );
    if (!stateResult.ok) {
        return c.json({ error: stateResult.error }, 400);
    }

    const stateData = stateResult.state;

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
    } satisfies Session;
    const sessionTtl =
        Number.parseInt(c.env.SESSION_TTL_SECONDS.toString(), 10) || 86400;
    const codeTtl =
        Number.parseInt(c.env.CODE_TTL_SECONDS.toString(), 10) || 300;

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
