import { exportJWK, generateKeyPair } from "jose";
import { KeyPairSchema } from "@/lib/schemas/keypair";

export async function ensureKey(
    env: CloudflareBindings
): Promise<{ kid: string; publicJwk: JsonWebKey; privateJwk: JsonWebKey }> {
    try {
        const existing = await env.AUTH_KV_KEYS.get("current", "json");
        if (existing) {
            const result = KeyPairSchema.safeParse(existing);

            if (result.success) {
                return result.data;
            }

            console.error("Failed to parse existing keypair:", result.error);
        }

        // If not found, generate new keypair
        const { publicKey, privateKey } = await generateKeyPair("RS256", {
            extractable: true,
        });
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
    } catch (error) {
        console.error("Error in ensureKey:", error);
        throw error;
    }
}
