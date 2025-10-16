import { Hono } from "hono";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.get("/", async (c) => {
    const cookie = c.req.header("Cookie") ?? "";
    const sid = /sid=([^;]+)/.exec(cookie)?.[1];

    if (sid) {
        await c.env.AUTH_KV_SESSIONS.delete(sid);
    }

    const clearCookie =
        "sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";

    return new Response(null, {
        status: 302,
        headers: {
            "Set-Cookie": clearCookie,
            Location: "/",
        },
    });
});

export default app;
