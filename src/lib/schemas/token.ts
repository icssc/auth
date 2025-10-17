import * as z from "zod";

export const TokenRequestSchema = z.object({
    grant_type: z.literal("authorization_code"),
    code: z.string(),
    redirect_uri: z.string().url(),
    client_id: z.string().optional(),
    code_verifier: z.string(),
});

export type TokenRequest = z.infer<typeof TokenRequestSchema>;
