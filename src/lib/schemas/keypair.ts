import * as z from "zod";

export const KeyPairSchema = z.object({
    kid: z.string(),
    publicJwk: z
        .object({
            kty: z.string(),
            n: z.string(),
            e: z.string(),
            kid: z.string(),
        })
        .loose(),
    privateJwk: z
        .object({
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
        })
        .loose(),
});
