import { generateCodeVerifier } from "arctic";
import { Hono } from "hono";
import { signOAuthStateParam } from "@/lib/auth/oauth-callback";
import { validateClient } from "@/lib/clients/validate";
import { createAppleClient, createGoogleClient } from "@/lib/oauth";
import { parseJsonWithSchema } from "@/lib/safe-json";
import type { AuthCode } from "@/lib/schemas/authcode";
import { AuthorizeQuerySchema } from "@/lib/schemas/authorize";
import { type Session, SessionSchema } from "@/lib/schemas/session";

const app = new Hono<{ Bindings: CloudflareBindings }>();

function errorRedirect(
    redirectUri: string,
    error: string,
    state?: string,
    errorDescription?: string
) {
    const url = new URL(redirectUri);
    url.searchParams.set("error", error);
    if (errorDescription) {
        url.searchParams.set("error_description", errorDescription);
    }
    if (state) {
        url.searchParams.set("state", state);
    }
    return url.toString();
}

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

    // Validate client+redirect_uri first — errors before this point
    // cannot be redirected because the redirect_uri is not yet trusted.
    const client = validateClient(client_id, redirect_uri);
    if (!client) {
        return c.json({ error: "unauthorized_client" }, 400);
    }

    const scopes = scope.split(" ");

    if (
        provider !== "google" &&
        scopes.some((s) => s.startsWith("https://www.googleapis.com/"))
    ) {
        return c.redirect(
            errorRedirect(
                redirect_uri,
                "invalid_scope",
                state,
                "Google-specific scopes can only be used with the Google provider"
            )
        );
    }

    const cookie = c.req.header("Cookie") ?? "";
    const sidMatch = /sid=([^;]+)/.exec(cookie);
    const sid = sidMatch?.[1];

    let session: Session | null = null;

    if (sid) {
        const sessionData = await c.env.AUTH_KV_SESSIONS.get(sid);
        if (sessionData) {
            session = parseJsonWithSchema(SessionSchema, sessionData);
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
        const sessionProvider = session.provider;

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
                return c.redirect(
                    errorRedirect(redirect_uri, "server_error", state)
                );
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
        return c.redirect(errorRedirect(redirect_uri, "login_required", state));
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

            const stateParamResult = await signOAuthStateParam(
                stateDataInner,
                c.env.STATE_SIGNING_SECRET
            );
            if (!stateParamResult.ok) {
                return c.redirect(
                    errorRedirect(redirect_uri, "server_error", state)
                );
            }

            const googleAuthUrl = google.createAuthorizationURL(
                stateParamResult.stateParam,
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

            const stateParamResult = await signOAuthStateParam(
                stateDataInner,
                c.env.STATE_SIGNING_SECRET
            );
            if (!stateParamResult.ok) {
                return c.redirect(
                    errorRedirect(redirect_uri, "server_error", state)
                );
            }

            const appleAuthUrl = apple.createAuthorizationURL(
                stateParamResult.stateParam,
                ["name", "email"]
            );
            appleAuthUrl.searchParams.set("response_mode", "form_post");

            return c.redirect(appleAuthUrl.toString());
        }
        default: {
            const _exhaustive: never = provider;
            return c.redirect(
                errorRedirect(redirect_uri, "server_error", state)
            );
        }
    }
});

export default app;
