import { Hono } from "hono";
import { isAllowedRedirectUrl } from "@/lib/clients/validate";
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

/**
 * Session check endpoint for cross-origin iframe communication.
 * Load this in a hidden iframe and it will postMessage the session status
 * back to the parent window.
 *
 * Query params:
 * - origin: The parent window's origin (required, must be an allowed redirect URL)
 *
 * @see {@link src/lib/examples/sso-client.ts}
 */
app.get("/check", async (c) => {
    const origin = c.req.query("origin");

    // Validate origin is from a registered client
    if (!origin || !isAllowedRedirectUrl(origin)) {
        return c.text("Invalid origin", 403);
    }

    const cookie = c.req.header("Cookie") ?? "";
    const sidMatch = /sid=([^;]+)/.exec(cookie);
    const sid = sidMatch?.[1];

    let sessionValid = false;
    let user = null;

    if (sid) {
        const sessionData = await c.env.AUTH_KV_SESSIONS.get(sid);
        if (sessionData) {
            const session = parseJsonWithSchema(SessionSchema, sessionData);
            if (session) {
                sessionValid = true;
                user = {
                    id: session.user_id,
                    email: session.email,
                    name: session.name,
                    picture: session.picture,
                };
            }
        }
    }

    // Return an HTML page that posts the message to the parent
    const html = `<!DOCTYPE html>
<html>
<head><title>Session Check</title></head>
<body>
<script>
    const message = {
        type: 'icssc-session-check',
        valid: ${sessionValid},
        user: ${user ? JSON.stringify(user) : "null"}
    };
    window.parent.postMessage(message, ${JSON.stringify(origin)});
</script>
</body>
</html>`;

    return c.html(html);
});

export default app;
