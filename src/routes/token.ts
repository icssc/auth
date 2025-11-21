import { createHash } from "crypto";
import { Hono } from "hono";
import { importJWK, SignJWT } from "jose";
import * as z from "zod";
import { AuthCodeSchema } from "@/lib/schemas/authcode";
import { KeyPairSchema } from "@/lib/schemas/keypair";
import { TokenRequestSchema } from "@/lib/schemas/token";

const app = new Hono<{ Bindings: CloudflareBindings }>();

const RefreshTokenDataSchema = z.object({
    user_id: z.string(),
    email: z.string(),
    name: z.string(),
    picture: z.string().optional(),
    client_id: z.string(),
    scope: z.string(),
    google_refresh_token: z.string().optional(),
});

app.post("/", async (c) => {
    const body = await c.req.parseBody();
    const parsed = TokenRequestSchema.safeParse(body);
    if (!parsed.success) {
        return c.json({ error: "invalid_request" }, 400);
    }

    const request = parsed.data;

    // Route to appropriate handler based on grant type
    if (request.grant_type === "authorization_code") {
        return handleAuthorizationCodeGrant(c, request);
    } else if (request.grant_type === "refresh_token") {
        return handleRefreshTokenGrant(c, request);
    }

    return c.json({ error: "unsupported_grant_type" }, 400);
});

/**
 * Handle authorization_code grant - initial token exchange
 */
async function handleAuthorizationCodeGrant(
    c: any,
    request: {
        code: string;
        client_id?: string;
        redirect_uri: string;
        code_verifier: string;
    }
) {
    const { code, client_id, redirect_uri, code_verifier } = request;

    const rawAuthCode = await c.env.AUTH_KV_AUTHCODES.get(code, "json");
    if (!rawAuthCode) {
        return c.json({ error: "invalid_authorization_code" }, 400);
    }
    const parsedAuthCode = AuthCodeSchema.safeParse(rawAuthCode);
    if (!parsedAuthCode.success) {
        return c.json({ error: "invalid_authorization_code" }, 400);
    }
    const authCode = parsedAuthCode.data;

    if (client_id && authCode.client_id !== client_id) {
        return c.json({ error: "invalid_authorization_code_client_id" }, 400);
    }

    if (authCode.redirect_uri !== redirect_uri) {
        return c.json(
            { error: "invalid_authorization_code_redirect_uri" },
            400
        );
    }

    const verifierHash = createHash("sha256")
        .update(code_verifier)
        .digest("base64url");
    if (verifierHash !== authCode.code_challenge) {
        return c.json({ error: "invalid_grant" }, 400);
    }

    await c.env.AUTH_KV_AUTHCODES.delete(code);

    const accessToken = crypto.randomUUID();
    const refreshToken = crypto.randomUUID();

    const rawKeypair = await c.env.AUTH_KV_KEYS.get("current", "json");
    if (!rawKeypair) {
        return c.json({ error: "server_error" }, 500);
    }
    const parsedKeypair = KeyPairSchema.safeParse(rawKeypair);
    if (!parsedKeypair.success) {
        return c.json({ error: "server_error" }, 500);
    }
    const keypair = parsedKeypair.data;
    const privateKey = await importJWK(keypair.privateJwk, "RS256");

    const now = Math.floor(Date.now() / 1000);
    const idToken = await new SignJWT({
        sub: authCode.user_id,
        email: authCode.email,
        name: authCode.name,
        picture: authCode.picture,
        aud: authCode.client_id,
        iss: c.env.ISSUER,
        iat: now,
        exp: now + Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
    })
        .setProtectedHeader({ alg: "RS256", kid: keypair.kid })
        .sign(privateKey);

    // Store access token
    await c.env.AUTH_KV_ACCESSTOKENS.put(
        accessToken,
        JSON.stringify({
            user_id: authCode.user_id,
            email: authCode.email,
            name: authCode.name,
            picture: authCode.picture,
            scope: authCode.scope,
            exp: now + Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
            google_access_token: authCode.google_access_token,
            google_refresh_token: authCode.google_refresh_token,
            google_token_expiry: authCode.google_token_expiry,
        }),
        {
            expirationTtl: Number.parseInt(
                c.env.TOKEN_TTL_SECONDS.toString(),
                10
            ),
        }
    );

    // Store refresh token
    await c.env.AUTH_KV_REFRESHTOKENS.put(
        refreshToken,
        JSON.stringify({
            user_id: authCode.user_id,
            email: authCode.email,
            name: authCode.name,
            picture: authCode.picture,
            client_id: authCode.client_id,
            scope: authCode.scope,
            google_refresh_token: authCode.google_refresh_token,
        }),
        {
            expirationTtl: Number.parseInt(
                c.env.REFRESH_TTL_SECONDS.toString(),
                10
            ),
        }
    );

    const response: {
        token_type: string;
        access_token: string;
        refresh_token: string;
        id_token: string;
        expires_in: number;
        google_access_token?: string;
        google_refresh_token?: string;
        google_token_expiry?: number;
    } = {
        token_type: "Bearer",
        access_token: accessToken,
        refresh_token: refreshToken,
        id_token: idToken,
        expires_in: Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
    };

    if (authCode.google_access_token) {
        response.google_access_token = authCode.google_access_token;
    }
    if (authCode.google_refresh_token) {
        response.google_refresh_token = authCode.google_refresh_token;
    }
    if (authCode.google_token_expiry) {
        response.google_token_expiry = authCode.google_token_expiry;
    }

    return c.json(response, 200, {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "Content-Type": "application/json",
    });
}

/**
 * Handle refresh_token grant - refresh Google tokens
 */
async function handleRefreshTokenGrant(
    c: any,
    request: { refresh_token: string; client_id?: string }
) {
    const { refresh_token, client_id } = request;

    // Validate refresh token
    const rawRefreshData = await c.env.AUTH_KV_REFRESHTOKENS.get(refresh_token);
    if (!rawRefreshData) {
        return c.json({ error: "invalid_grant" }, 400);
    }

    let refreshData;
    try {
        const parsed = JSON.parse(rawRefreshData);
        const result = RefreshTokenDataSchema.safeParse(parsed);
        if (!result.success) {
            return c.json({ error: "invalid_grant" }, 400);
        }
        refreshData = result.data;
    } catch (_e) {
        return c.json({ error: "invalid_grant" }, 400);
    }

    // Validate client_id if provided
    if (client_id && refreshData.client_id !== client_id) {
        return c.json({ error: "invalid_grant" }, 400);
    }

    let newGoogleAccessToken = undefined;
    let newGoogleTokenExpiry = undefined;

    // If we have a Google refresh token, refresh it
    if (refreshData.google_refresh_token) {
        try {
            const googleResponse = await fetch(
                "https://oauth2.googleapis.com/token",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    body: new URLSearchParams({
                        grant_type: "refresh_token",
                        refresh_token: refreshData.google_refresh_token,
                        client_id: c.env.GOOGLE_CLIENT_ID,
                        client_secret: c.env.GOOGLE_CLIENT_SECRET,
                    }),
                }
            );

            if (googleResponse.ok) {
                const googleData = (await googleResponse.json()) as {
                    access_token?: string;
                    expires_in?: number;
                };
                newGoogleAccessToken = googleData.access_token;
                // Google returns expires_in in seconds
                newGoogleTokenExpiry =
                    Date.now() + (googleData.expires_in ?? 3600) * 1000;
            } else {
                console.error(
                    "Failed to refresh Google token:",
                    await googleResponse.text()
                );
            }
        } catch (error) {
            console.error("Error refreshing Google token:", error);
        }
    }

    // Generate new access token
    const newAccessToken = crypto.randomUUID();

    const rawKeypair = await c.env.AUTH_KV_KEYS.get("current", "json");
    if (!rawKeypair) {
        return c.json({ error: "server_error" }, 500);
    }
    const parsedKeypair = KeyPairSchema.safeParse(rawKeypair);
    if (!parsedKeypair.success) {
        return c.json({ error: "server_error" }, 500);
    }
    const keypair = parsedKeypair.data;
    const privateKey = await importJWK(keypair.privateJwk, "RS256");

    const now = Math.floor(Date.now() / 1000);
    const idToken = await new SignJWT({
        sub: refreshData.user_id,
        email: refreshData.email,
        name: refreshData.name,
        picture: refreshData.picture,
        aud: refreshData.client_id,
        iss: c.env.ISSUER,
        iat: now,
        exp: now + Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
    })
        .setProtectedHeader({ alg: "RS256", kid: keypair.kid })
        .sign(privateKey);

    // Store new access token
    await c.env.AUTH_KV_ACCESSTOKENS.put(
        newAccessToken,
        JSON.stringify({
            user_id: refreshData.user_id,
            email: refreshData.email,
            name: refreshData.name,
            picture: refreshData.picture,
            scope: refreshData.scope,
            exp: now + Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
            google_access_token: newGoogleAccessToken,
            google_refresh_token: refreshData.google_refresh_token,
            google_token_expiry: newGoogleTokenExpiry,
        }),
        {
            expirationTtl: Number.parseInt(
                c.env.TOKEN_TTL_SECONDS.toString(),
                10
            ),
        }
    );

    const response: {
        token_type: string;
        access_token: string;
        id_token: string;
        expires_in: number;
        google_access_token?: string;
        google_refresh_token?: string;
        google_token_expiry?: number;
    } = {
        token_type: "Bearer",
        access_token: newAccessToken,
        id_token: idToken,
        expires_in: Number.parseInt(c.env.TOKEN_TTL_SECONDS.toString(), 10),
    };

    if (newGoogleAccessToken) {
        response.google_access_token = newGoogleAccessToken;
    }
    if (refreshData.google_refresh_token) {
        response.google_refresh_token = refreshData.google_refresh_token;
    }
    if (newGoogleTokenExpiry) {
        response.google_token_expiry = newGoogleTokenExpiry;
    }

    return c.json(response, 200, {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "Content-Type": "application/json",
    });
}

export default app;
