import { exportJWK, generateKeyPair } from "jose";
import { z } from "zod";
import { tryCatch } from "@/lib/try-catch";

const KeyPairSchema = z.object({
    kid: z.string(),
    publicJwk: z.object({
        kty: z.string(),
        n: z.string(),
        e: z.string(),
        kid: z.string(),
    }),
    privateJwk: z.object({
        kty: z.string(),
        n: z.string(),
        e: z.string(),
        d: z.string(),
        p: z.string(),
        q: z.string(),
        dp: z.string(),
        dq: z.string(),
        qi: z.string(),
        kid: z.string(),
    }),
});

export async function ensureKey(
    env: CloudflareBindings
): Promise<{ kid: string; publicJwk: JsonWebKey; privateJwk: JsonWebKey }> {
    const existing = await env.AUTH_KV_KEYS.get("current", "json");
    if (existing) {
        const { data, error } = await tryCatch(
            KeyPairSchema.parseAsync(JSON.parse(existing as string))
        );

        if (!error) {
            return data;
        }

        // TODO (@kevinwu098): log error
    }

    // If not found, generate new keypair
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const kid = crypto.randomUUID();
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    publicJwk.kid = kid;
    privateJwk.kid = kid;

    await env.AUTH_KV_KEYS.put(
        "current",
        JSON.stringify({ kid, publicJwk, privateJwk })
    );

    return { kid, publicJwk, privateJwk };
}
