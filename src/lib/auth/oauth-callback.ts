import { validateClient } from "@/lib/clients/validate";
import type { AuthCode } from "@/lib/schemas/authcode";
import type { Provider } from "@/lib/schemas/providers";
import type { StateInner } from "@/lib/schemas/state";
import { StateDataSchema } from "@/lib/schemas/state";
import { tryCatch, tryCatchSync } from "@/lib/try-catch";
import {
    arrayBufferToBase64,
    base64ToArrayBuffer,
    hmacFromSecret,
} from "@/lib/verify-state";

export type OAuthCallbackStateError = "invalid_state" | "unauthorized_client";

export type VerifyOAuthCallbackStateResult<P extends Provider> =
    | { ok: true; state: Extract<StateInner, { provider: P }> }
    | { ok: false; error: OAuthCallbackStateError };

/**
 * Decode, validate shape, check provider, verify HMAC, and ensure the OAuth client is registered.
 * Callers cross this seam for every IdP callback that uses signed state from /authorize.
 */
export async function verifyOAuthCallbackState<P extends Provider>(
    stateParam: string,
    expectedProvider: P,
    stateSecret: string
): Promise<VerifyOAuthCallbackStateResult<P>> {
    const decoded = tryCatchSync(() => JSON.parse(atob(stateParam)) as unknown);
    if (decoded.error || decoded.data === null) {
        return { ok: false, error: "invalid_state" };
    }

    const rawState = decoded.data as { inner?: unknown };
    if (rawState.inner === undefined) {
        return { ok: false, error: "invalid_state" };
    }

    const parsedStateData = StateDataSchema.safeParse(rawState);
    if (!parsedStateData.success) {
        return { ok: false, error: "invalid_state" };
    }

    const { digest: stateDataDigest, inner: stateData } = parsedStateData.data;

    if (stateData.provider !== expectedProvider) {
        return { ok: false, error: "invalid_state" };
    }

    const innerForHmac = JSON.stringify(rawState.inner);
    const signatureResult = tryCatchSync(() =>
        base64ToArrayBuffer(stateDataDigest)
    );
    if (signatureResult.error) {
        return { ok: false, error: "invalid_state" };
    }

    const verifyResult = await tryCatch(
        crypto.subtle.verify(
            "HMAC",
            await hmacFromSecret(stateSecret),
            signatureResult.data,
            new TextEncoder().encode(innerForHmac)
        )
    );

    if (!verifyResult.data) {
        return { ok: false, error: "invalid_state" };
    }

    const client = validateClient(stateData.client_id, stateData.redirect_uri);
    if (!client) {
        return { ok: false, error: "unauthorized_client" };
    }

    return {
        ok: true,
        state: stateData as Extract<StateInner, { provider: P }>,
    };
}

export type FinalizeBrowserOAuthLoginArgs<S extends object> = {
    kvSessions: KVNamespace;
    kvAuthCodes: KVNamespace;
    sessionTtlSeconds: number;
    codeTtlSeconds: number;
    sessionData: S;
    authCode: AuthCode;
    redirectUri: string;
    clientState: string | undefined;
    requestUrl: URL;
};

/**
 * Persist session and authorization code, then produce redirect Location and Set-Cookie
 * for the browser leg of the OAuth code flow.
 */
export async function finalizeBrowserOAuthLogin<S extends object>(
    args: FinalizeBrowserOAuthLoginArgs<S>
): Promise<{ location: string; setCookie: string }> {
    const sessionId = crypto.randomUUID();
    const authCodeId = crypto.randomUUID();

    await args.kvSessions.put(sessionId, JSON.stringify(args.sessionData), {
        expirationTtl: args.sessionTtlSeconds,
    });

    await args.kvAuthCodes.put(authCodeId, JSON.stringify(args.authCode), {
        expirationTtl: args.codeTtlSeconds,
    });

    const redirectUrl = new URL(args.redirectUri);
    redirectUrl.searchParams.set("code", authCodeId);
    if (args.clientState) {
        redirectUrl.searchParams.set("state", args.clientState);
    }

    const cookieDomain = args.requestUrl.hostname;
    const isSecure = args.requestUrl.protocol === "https:";
    const setCookie = isSecure
        ? `sid=${sessionId}; Domain=${cookieDomain}; HttpOnly; Secure; SameSite=None; Max-Age=${args.sessionTtlSeconds}; Path=/`
        : `sid=${sessionId}; HttpOnly; SameSite=Lax; Max-Age=${args.sessionTtlSeconds}; Path=/`;

    return { location: redirectUrl.toString(), setCookie };
}

export async function signOAuthStateParam(
    inner: StateInner,
    stateSecret: string
): Promise<
    { ok: true; stateParam: string } | { ok: false; error: "invalid_state" }
> {
    const stateData = {
        digest: await crypto.subtle
            .sign(
                "HMAC",
                await hmacFromSecret(stateSecret),
                new TextEncoder().encode(JSON.stringify(inner))
            )
            .then(arrayBufferToBase64),
        inner,
    };

    const encoded = tryCatchSync(() => btoa(JSON.stringify(stateData)));
    if (encoded.error) {
        return { ok: false, error: "invalid_state" };
    }

    return { ok: true, stateParam: encoded.data };
}
