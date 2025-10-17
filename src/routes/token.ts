import { createHash } from "crypto";
import { Hono } from "hono";
import { importJWK, SignJWT } from "jose";
import { AuthCodeSchema } from "@/lib/schemas/authcode";
import { KeyPairSchema } from "@/lib/schemas/keypair";
import { TokenRequestSchema } from "@/lib/schemas/token";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.post("/", async (c) => {
    const body = await c.req.parseBody();
    const parsed = TokenRequestSchema.safeParse(body);
    if (!parsed.success) {
        return c.json({ error: "invalid_request" }, 400);
    }

    const { code, client_id, redirect_uri, code_verifier } = parsed.data;

    const rawAuthCode = await c.env.AUTH_KV_AUTHCODES.get(code, "json");
    if (!rawAuthCode) {
        return c.json({ error: "invalid_authorization_code" }, 400);
    }
    const authCode = AuthCodeSchema.parse(rawAuthCode);

    if (
        authCode.client_id !== client_id ||
        authCode.redirect_uri !== redirect_uri
    ) {
        return c.json({ error: "invalid_authorization_code_data" }, 400);
    }

    const verifierHash = createHash("sha256")
        .update(code_verifier)
        .digest("base64url");
    if (verifierHash !== authCode.code_challenge) {
        return c.json({ error: "invalid_grant" }, 400);
    }

    await c.env.AUTH_KV_AUTHCODES.delete(code);

    const accessToken = crypto.randomUUID();

    const rawKeypair = await c.env.AUTH_KV_KEYS.get("current", "json");
    if (!rawKeypair) {
        return c.json({ error: "server_error" }, 500);
    }
    const keypair = KeyPairSchema.parse(rawKeypair);

    const privateKey = await importJWK(keypair.privateJwk, "RS256");

    const now = Math.floor(Date.now() / 1000);
    const idToken = await new SignJWT({
        sub: authCode.user_id,
        aud: client_id,
        iss: c.env.ISSUER,
        iat: now,
        exp: now + Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
    })
        .setProtectedHeader({ alg: "RS256", kid: keypair.kid })
        .sign(privateKey);

    await c.env.AUTH_KV_ACCESSTOKENS.put(
        accessToken,
        JSON.stringify({
            user_id: authCode.user_id,
            email: authCode.email,
            name: authCode.name,
            scope: authCode.scope,
            exp: now + Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
        }),
        {
            expirationTtl: Number.parseInt(
                c.env.TOKEN_TTL_SECONDS.toString(),
                10
            ),
        }
    );

    return c.json(
        {
            token_type: "Bearer",
            access_token: accessToken,
            id_token: idToken,
            expires_in: Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
        },
        200,
        {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
            "Content-Type": "application/json",
        }
    );
});

export default app;
