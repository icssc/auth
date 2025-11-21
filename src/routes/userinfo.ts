import { Hono } from "hono";
import * as z from "zod";

const app = new Hono<{ Bindings: CloudflareBindings }>();

const AccessTokenDataSchema = z.object({
    user_id: z.string(),
    email: z.string(),
    name: z.string(),
    picture: z.string().optional(),
    scope: z.string(),
    exp: z.number(),
});

app.get("/", async (c) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return c.json({ error: "invalid_token" }, 401, {
            "WWW-Authenticate": 'Bearer error="invalid_token"',
        });
    }

    const accessToken = authHeader.substring(7); // Remove "Bearer " prefix

    const rawTokenData = await c.env.AUTH_KV_ACCESSTOKENS.get(accessToken);
    if (!rawTokenData) {
        return c.json({ error: "invalid_token" }, 401, {
            "WWW-Authenticate": 'Bearer error="invalid_token"',
        });
    }

    // Parse and validate token data
    let tokenData;
    try {
        const parsed = JSON.parse(rawTokenData);
        const result = AccessTokenDataSchema.safeParse(parsed);
        if (!result.success) {
            return c.json({ error: "invalid_token" }, 401, {
                "WWW-Authenticate": 'Bearer error="invalid_token"',
            });
        }
        tokenData = result.data;
    } catch (_e) {
        return c.json({ error: "invalid_token" }, 401, {
            "WWW-Authenticate": 'Bearer error="invalid_token"',
        });
    }

    const now = Math.floor(Date.now() / 1000);
    if (tokenData.exp < now) {
        return c.json(
            { error: "invalid_token", error_description: "Token expired" },
            401,
            {
                "WWW-Authenticate":
                    'Bearer error="invalid_token", error_description="Token expired"',
            }
        );
    }

    const scopes = tokenData.scope.split(" ");
    const response: Record<string, string | undefined> = {
        sub: tokenData.user_id,
        picture: tokenData.picture,
    };
    if (scopes.includes("profile")) {
        response.name = tokenData.name;
    }
    if (scopes.includes("email")) {
        response.email = tokenData.email;
    }

    return c.json(response, 200, {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "Content-Type": "application/json",
    });
});

export default app;
