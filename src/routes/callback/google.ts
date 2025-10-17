import { Hono } from "hono";
import * as z from "zod";
import { createGoogleOAuth2Client } from "@/lib/oauth";
import type { AuthCode } from "@/lib/schemas/authcode";
import { tryCatch } from "@/lib/try-catch";

const app = new Hono<{ Bindings: CloudflareBindings }>();

const StateDataSchema = z.object({
    client_id: z.string(),
    redirect_uri: z.string(),
    state: z.string().optional(),
    code_challenge: z.string(),
    scope: z.string(),
});

app.get("/", async (c) => {
    const { code, state: stateParam, error } = c.req.query();

    if (error) {
        return c.json({ error: "google_oauth_error", description: error }, 400);
    }

    if (!code || !stateParam) {
        return c.json({ error: "invalid_request" }, 400);
    }

    const { data: stateData, error: stateDataError } = await tryCatch(
        (async () => {
            const decoded = JSON.parse(atob(stateParam));
            return StateDataSchema.parseAsync(decoded);
        })()
    );

    if (stateDataError) {
        return c.json({ error: "invalid_state" }, 400);
    }

    const oauth2Client = createGoogleOAuth2Client(c.env);
    const { data: tokenResult, error: tokenError } = await tryCatch(
        oauth2Client.getToken(code)
    );
    if (tokenError || !tokenResult) {
        return c.json({ error: "google_token_exchange_failed" }, 500);
    }

    oauth2Client.setCredentials(tokenResult.tokens);
    const { data: userInfoResult, error: userInfoError } = await tryCatch(
        oauth2Client.request<{
            id: string;
            email: string;
            name: string;
        }>({
            url: "https://www.googleapis.com/oauth2/v2/userinfo",
        })
    );
    if (userInfoError || !userInfoResult) {
        return c.json({ error: "google_userinfo_failed" }, 500);
    }

    const userInfo = userInfoResult.data;
    const userId = `google_${userInfo.id}`;

    const sessionId = crypto.randomUUID();
    const sessionData = {
        user_id: userId,
        email: userInfo.email,
        name: userInfo.name,
    };
    const sessionTtl =
        Number.parseInt(c.env.SESSION_TTL_SECONDS.toString(), 10) || 86400;
    await c.env.AUTH_KV_SESSIONS.put(sessionId, JSON.stringify(sessionData), {
        expirationTtl: sessionTtl,
    });

    const authCode = crypto.randomUUID();
    const codeData = {
        user_id: userId,
        email: userInfo.email,
        name: userInfo.name,
        client_id: stateData.client_id,
        redirect_uri: stateData.redirect_uri,
        code_challenge: stateData.code_challenge,
        scope: stateData.scope,
        created_at: Date.now(),
    } satisfies AuthCode;

    await c.env.AUTH_KV_AUTHCODES.put(authCode, JSON.stringify(codeData), {
        expirationTtl:
            Number.parseInt(c.env.CODE_TTL_SECONDS.toString(), 10) || 300,
    });

    const redirectUrl = new URL(stateData.redirect_uri);
    redirectUrl.searchParams.set("code", authCode);
    if (stateData.state) redirectUrl.searchParams.set("state", stateData.state);

    const response = c.redirect(redirectUrl.toString(), 302);
    response.headers.set(
        "Set-Cookie",
        `sid=${sessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=${sessionTtl}; Path=/`
    );
    return response;
});

export default app;
