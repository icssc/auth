import { Hono } from "hono";
import { cors } from "hono/cors";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.use(
    "/*",
    cors({
        origin: (origin) => origin,
        allowMethods: ["GET", "POST", "OPTIONS"],
        credentials: true,
    })
);

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

    const session = JSON.parse(sessionData);
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
