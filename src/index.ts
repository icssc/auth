import { Hono } from "hono";
import { ensureKey } from "@/lib/ensureKey";
import authorizeRoutes from "@/routes/authorize";
import callbackRoutes from "@/routes/callback";
import logoutRoutes from "@/routes/logout";
import tokenRoutes from "@/routes/token";
import userinfoRoutes from "@/routes/userinfo";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.route("/authorize", authorizeRoutes);
app.route("/callback", callbackRoutes);
app.route("/token", tokenRoutes);
app.route("/userinfo", userinfoRoutes);
app.route("/logout", logoutRoutes);

app.get("/.well-known/openid-configuration", (c) => {
    const iss = c.env.ISSUER;

    const config = {
        issuer: iss,
        authorization_endpoint: `${iss}/authorize`,
        token_endpoint: `${iss}/token`,
        userinfo_endpoint: `${iss}/userinfo`,
        jwks_uri: `${iss}/jwks.json`,
        scopes_supported: ["openid", "profile", "email"],
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
        code_challenge_methods_supported: ["S256"],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "name", "email"],
    };

    return c.json(config, 200, {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "Content-Type": "application/json",
    });
});

app.get("/jwks.json", async (c) => {
    const { publicJwk } = await ensureKey(c.env);

    const jwks = {
        keys: [
            {
                ...publicJwk,
                alg: "RS256",
                use: "sig",
            },
        ],
    };

    return c.json(jwks, 200, {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "Content-Type": "application/json",
    });
});

export default app;
