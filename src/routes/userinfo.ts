import { eq } from "drizzle-orm";
import { Hono } from "hono";
import * as z from "zod";
import { getDb } from "@/db";
import { users } from "@/db/schema";

const app = new Hono<{ Bindings: CloudflareBindings }>();

const TokenSchema = z.object({
    user_id: z.string(),
    scope: z.string(),
    exp: z.number(),
});

app.get("/", async (c) => {
    const auth = c.req.header("Authorization");
    if (!auth || !auth.startsWith("Bearer ")) {
        return c.json(
            {
                error: "invalid_request",
                error_description: "Missing bearer token",
            },
            401
        );
    }

    const token = auth.split(" ")[1];
    if (!token) {
        return c.json({ error: "invalid_request" }, 401);
    }

    const accessTokenRaw = await c.env.AUTH_KV_ACCESSTOKENS.get(token, "json");
    if (!accessTokenRaw) {
        return c.json({ error: "invalid_token" }, 401);
    }
    const accessToken = TokenSchema.parse(accessTokenRaw);

    const now = Math.floor(Date.now() / 1000);
    if (accessToken.exp < now) {
        return c.json({ error: "invalid_token" }, 401);
    }

    const db = getDb(c.env.AUTH_DB);
    const user = await db
        .select()
        .from(users)
        .where(eq(users.id, accessToken.user_id))
        .get();

    if (!user) {
        return c.json({ error: "user_not_found" }, 404);
    }

    const response = {
        sub: user.id,
        email: user.email,
        name: user.name,
    };

    return c.json(response, 200, {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "Content-Type": "application/json",
    });
});

export default app;
