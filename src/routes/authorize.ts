import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { getDb } from "@/db";
import { clients } from "@/db/schema";
import { createGoogleOAuth2Client } from "@/lib/oauth";
import type { AuthCodeSchema } from "@/lib/schemas/authcode";

const app = new Hono<{ Bindings: CloudflareBindings }>();

const AuthorizeQuerySchema = z.object({
    response_type: z.literal("code"),
    client_id: z.string(),
    redirect_uri: z.string().url(),
    scope: z.string(),
    state: z.string().optional(),
    code_challenge: z.string(),
    code_challenge_method: z.literal("S256"),
});

const StateDataSchema = z.object({
    client_id: z.string(),
    redirect_uri: z.string(),
    state: z.string().optional(),
    code_challenge: z.string(),
    scope: z.string(),
});

app.get("/", async (c) => {
    const query = c.req.query();
    const parsed = AuthorizeQuerySchema.safeParse(query);
    if (!parsed.success) {
        return c.json({ error: "invalid_request" }, 400);
    }

    const { client_id, redirect_uri, state, code_challenge, scope } =
        parsed.data;

    const db = getDb(c.env.AUTH_DB);
    const client = await db
        .select()
        .from(clients)
        .where(eq(clients.clientId, client_id))
        .get();

    if (!client || client.redirectUri !== redirect_uri) {
        return c.json({ error: "unauthorized_client" }, 400);
    }

    // 2️⃣ Check session
    const cookie = c.req.header("Cookie") ?? "";
    const sidMatch = /sid=([^;]+)/.exec(cookie);
    const sid = sidMatch?.[1];

    let session: { user_id: string; email: string; name: string } | null = null;

    if (sid) {
        const sessionData = await c.env.AUTH_KV_SESSIONS.get(sid);
        if (sessionData) {
            session = JSON.parse(sessionData);
        }
    }

    if (!session) {
        const oauth2Client = createGoogleOAuth2Client(c.env);
        const stateData = {
            client_id,
            redirect_uri,
            state,
            code_challenge,
            scope,
        } satisfies z.infer<typeof StateDataSchema>;

        const googleAuthUrl = oauth2Client.generateAuthUrl({
            access_type: "online",
            scope: ["openid", "email", "profile"],
            prompt: "consent",
            state: btoa(JSON.stringify(stateData)),
        });

        return c.redirect(googleAuthUrl);
    }

    const code = crypto.randomUUID();
    const authCode = {
        user_id: session.user_id,
        client_id,
        redirect_uri,
        code_challenge,
        scope,
        created_at: Date.now(),
    } satisfies z.infer<typeof AuthCodeSchema>;
    await c.env.AUTH_KV_AUTHCODES.put(code, JSON.stringify(authCode), {
        expirationTtl:
            Number.parseInt(c.env.CODE_TTL_SECONDS.toString(), 10) || 300,
    });

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) {
        redirectUrl.searchParams.set("state", state);
    }
    return c.redirect(redirectUrl.toString());
});

export default app;
