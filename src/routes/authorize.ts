import { Hono } from "hono";
import { validateClient } from "@/lib/clients";
import { createGoogleOAuth2Client } from "@/lib/oauth";
import type { AuthCode } from "@/lib/schemas/authcode";
import { AuthorizeQuerySchema } from "@/lib/schemas/authorize";
import type { StateData } from "@/lib/schemas/state";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.get("/", async (c) => {
    const query = c.req.query();
    const parsed = AuthorizeQuerySchema.safeParse(query);
    if (!parsed.success) {
        return c.json({ error: "invalid_request" }, 400);
    }

    const { client_id, redirect_uri, state, code_challenge, scope } =
        parsed.data;

    const client = validateClient(client_id, redirect_uri);
    if (!client) {
        return c.json({ error: "unauthorized_client" }, 400);
    }

    const cookie = c.req.header("Cookie") ?? "";
    const sidMatch = /sid=([^;]+)/.exec(cookie);
    const sid = sidMatch?.[1];

    let session: {
        user_id: string;
        email: string;
        name: string;
        picture?: string;
        google_access_token?: string;
        google_refresh_token?: string;
        google_token_expiry?: number;
        scope: string;
    } | null = null;

    // `sid` is session id
    if (sid) {
        const sessionData = await c.env.AUTH_KV_SESSIONS.get(sid);
        if (sessionData) {
            session = JSON.parse(sessionData);
        }
    }

    const normalizeScope = (s: string) => s.split(" ").sort().join(" ");

    if (!session || normalizeScope(session.scope) !== normalizeScope(scope)) {
        const oauth2Client = createGoogleOAuth2Client(c.env);
        const stateData = {
            client_id,
            redirect_uri,
            state,
            code_challenge,
            scope,
        } satisfies StateData;

        const googleAuthUrl = oauth2Client.generateAuthUrl({
            access_type: "offline", // Request refresh token
            scope: scope.split(" "),
            prompt: "consent",
            state: btoa(JSON.stringify(stateData)),
        });

        return c.redirect(googleAuthUrl);
    }

    const code = crypto.randomUUID();
    const authCode = {
        user_id: session.user_id,
        email: session.email,
        name: session.name,
        picture: session.picture,
        client_id,
        redirect_uri,
        code_challenge,
        scope,
        created_at: Date.now(),
        google_access_token: session.google_access_token,
        google_refresh_token: session.google_refresh_token,
        google_token_expiry: session.google_token_expiry,
    } satisfies AuthCode;
    await c.env.AUTH_KV_AUTHCODES.put(code, JSON.stringify(authCode), {
        expirationTtl: Number.parseInt(c.env.CODE_TTL_SECONDS.toString(), 10),
    });

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) {
        redirectUrl.searchParams.set("state", state);
    }
    return c.redirect(redirectUrl.toString());
});

export default app;
