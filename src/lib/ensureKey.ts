import { exportJWK, generateKeyPair } from "jose";
import { KeyPairSchema } from "@/lib/schemas/keypair";
import { tryCatch } from "@/lib/try-catch";

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
