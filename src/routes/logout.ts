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
    const sid = /sid=([^;]+)/.exec(cookie)?.[1];

    if (sid) {
        await c.env.AUTH_KV_SESSIONS.delete(sid);
    }

    const clearCookie =
        "sid=; Domain=auth.icssc.club; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";

    const redirectTo = c.req.query("redirect_to");

    if (redirectTo) {
        return new Response(null, {
            status: 302,
            headers: {
                "Set-Cookie": clearCookie,
                Location: redirectTo,
            },
        });
    }

    return c.json({ success: true, message: "Logged out successfully" }, 200, {
        "Set-Cookie": clearCookie,
    });
});

export default app;
