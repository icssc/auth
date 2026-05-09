import { generateCodeVerifier } from "arctic";
import { Hono } from "hono";
import { validateClient } from "@/lib/clients";
import { createAppleClient, createGoogleClient } from "@/lib/oauth";
import type { AuthCode } from "@/lib/schemas/authcode";
import { AuthorizeQuerySchema } from "@/lib/schemas/authorize";
import { type Provider } from "@/lib/schemas/providers";
import type { StateData } from "@/lib/schemas/state";
import { tryCatchSync } from "@/lib/try-catch";
import { arrayBufferToBase64, hmacFromSecret } from "@/lib/verify-state";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.get("/", async (c) => {
    const query = c.req.query();
    const parsed = AuthorizeQuerySchema.safeParse(query);
    if (!parsed.success) {
        return c.json({ error: "invalid_request" }, 400);
    }

    const {
        client_id,
        redirect_uri,
        state,
        code_challenge,
        scope,
        prompt,
        provider,
    } = parsed.data;

    const scopes = scope.split(" ");

    if (
        provider !== "google" &&
        scopes.some((s) => s.startsWith("https://www.googleapis.com/"))
    ) {
        return c.json(
            {
                error: "invalid_scope",
                error_description:
                    "Google-specific scopes can only be used with the Google provider",
            },
            400
        );
    }

    const client = validateClient(client_id, redirect_uri);
    if (!client) {
        return c.json({ error: "unauthorized_client" }, 400);
    }

    const cookie = c.req.header("Cookie") ?? "";
    const sidMatch = /sid=([^;]+)/.exec(cookie);
    const sid = sidMatch?.[1];

    let session: {
        user_id: string;
        email: string;
        name: string;
        picture?: string;
        provider?: Provider;
        google_access_token?: string;
        google_refresh_token?: string;
        google_token_expiry?: number;
        scope: string;
    } | null = null;

    if (sid) {
        const sessionData = await c.env.AUTH_KV_SESSIONS.get(sid);
        if (sessionData) {
            session = JSON.parse(sessionData);
        }
    }

    const scopesSatisfied = (sessionScope: string, requestedScope: string) => {
        const sessionScopes = new Set(sessionScope.split(" "));
        const requestedScopes = requestedScope.split(" ");
        return requestedScopes.every((s) => sessionScopes.has(s));
    };

    if (
        session &&
        scopesSatisfied(session.scope, scope) &&
        prompt !== "consent"
    ) {
        const code = crypto.randomUUID();
        const sessionProvider = session.provider ?? "google";

        let authCode: AuthCode;
        switch (sessionProvider) {
            case "google":
                authCode = {
                    provider: "google",
                    user_id: session.user_id,
                    email: session.email,
                    name: session.name,
                    picture: session.picture,
                    client_id,
                    redirect_uri,
                    code_challenge,
                    scope,
                    created_at: Date.now(),
                    google_access_token: session.google_access_token,
                    google_refresh_token: session.google_refresh_token,
                    google_token_expiry: session.google_token_expiry,
                };
                break;
            case "apple":
                authCode = {
                    provider: "apple",
                    user_id: session.user_id,
                    email: session.email,
                    name: session.name,
                    picture: session.picture,
                    client_id,
                    redirect_uri,
                    code_challenge,
                    scope,
                    created_at: Date.now(),
                };
                break;
            default: {
                const _exhaustive: never = sessionProvider;
                return c.json({ error: "invalid_provider" }, 400);
            }
        }

        await c.env.AUTH_KV_AUTHCODES.put(code, JSON.stringify(authCode), {
            expirationTtl: Number.parseInt(
                c.env.CODE_TTL_SECONDS.toString(),
                10
            ),
        });

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set("code", code);
        if (state) {
            redirectUrl.searchParams.set("state", state);
        }
        return c.redirect(redirectUrl.toString());
    }

    if (prompt === "none") {
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set("error", "login_required");
        if (state) {
            redirectUrl.searchParams.set("state", state);
        }
        return c.redirect(redirectUrl.toString());
    }

    switch (provider) {
        case "google": {
            const codeVerifier = generateCodeVerifier();
            const google = createGoogleClient(c.env);

            const stateDataInner = {
                provider: "google" as const,
                client_id,
                redirect_uri,
                state,
                code_challenge,
                scope,
                code_verifier: codeVerifier,
            };

            const stateData = {
                digest: await crypto.subtle
                    .sign(
                        "HMAC",
                        await hmacFromSecret(c.env.GOOGLE_CLIENT_SECRET),
                        new TextEncoder().encode(JSON.stringify(stateDataInner))
                    )
                    .then(arrayBufferToBase64),
                inner: stateDataInner,
            } satisfies StateData;

            const stateParamResult = tryCatchSync(() =>
                btoa(JSON.stringify(stateData))
            );
            if (stateParamResult.error) {
                return c.json({ error: "invalid_state" }, 400);
            }

            const googleAuthUrl = google.createAuthorizationURL(
                stateParamResult.data,
                codeVerifier,
                scopes
            );
            googleAuthUrl.searchParams.set("access_type", "offline");
            googleAuthUrl.searchParams.set("prompt", "consent");

            return c.redirect(googleAuthUrl.toString());
        }
        case "apple": {
            const apple = createAppleClient(c.env);

            const stateDataInner = {
                provider: "apple" as const,
                client_id,
                redirect_uri,
                state,
                code_challenge,
                scope,
            };

            const stateData = {
                digest: await crypto.subtle
                    .sign(
                        "HMAC",
                        await hmacFromSecret(c.env.GOOGLE_CLIENT_SECRET),
                        new TextEncoder().encode(JSON.stringify(stateDataInner))
                    )
                    .then(arrayBufferToBase64),
                inner: stateDataInner,
            } satisfies StateData;

            const stateParamResult = tryCatchSync(() =>
                btoa(JSON.stringify(stateData))
            );
            if (stateParamResult.error) {
                return c.json({ error: "invalid_state" }, 400);
            }

            const appleAuthUrl = apple.createAuthorizationURL(
                stateParamResult.data,
                ["name", "email"]
            );
            appleAuthUrl.searchParams.set("response_mode", "form_post");

            return c.redirect(appleAuthUrl.toString());
        }
        default: {
            const _exhaustive: never = provider;
            return c.json({ error: "invalid_provider" }, 400);
        }
    }
});

export default app;
