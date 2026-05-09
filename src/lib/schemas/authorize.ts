import * as z from "zod";

import { PROVIDERS } from "@/lib/schemas/providers";

export const AuthorizeQuerySchema = z.object({
    response_type: z.literal("code"),
    client_id: z.string(),
    redirect_uri: z.string().url(),
    scope: z.string(),
    state: z.string().optional(),
    code_challenge: z.string(),
    code_challenge_method: z.literal("S256"),
    prompt: z.enum(["none", "consent"]).optional(),
    provider: z.enum(PROVIDERS).default("google"),
});

export type AuthorizeQuery = z.infer<typeof AuthorizeQuerySchema>;
