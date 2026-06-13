import { Hono } from "hono";
import { registeredClientCors } from "@/lib/cors";
import { parseJsonWithSchema } from "@/lib/safe-json";
import { SessionSchema } from "@/lib/schemas/session";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.use("/*", registeredClientCors);

app.get("/", async (c) => {
    const cookie = c.req.header("Cookie") ?? "";
    const sidMatch = /sid=([^;]+)/.exec(cookie);
    const sid = sidMatch?.[1];

    if (!sid) {
        return c.json({ valid: false }, 401);
    }

    const sessionData = await c.env.AUTH_KV_SESSIONS.get(sid);
    if (!sessionData) {
        return c.json({ valid: false }, 401);
    }

    const session = parseJsonWithSchema(SessionSchema, sessionData);
    if (!session) {
        return c.json({ valid: false }, 401);
    }

    return c.json(
        {
            valid: true,
            user: {
                id: session.user_id,
                email: session.email,
                name: session.name,
                picture: session.picture,
            },
        },
        200
    );
});

export default app;
