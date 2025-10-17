import * as z from "zod";

export const AuthorizeQuerySchema = z.object({
    response_type: z.literal("code"),
    client_id: z.string(),
    redirect_uri: z.string().url(),
    scope: z.string(),
    state: z.string().optional(),
    code_challenge: z.string(),
    code_challenge_method: z.literal("S256"),
});

export type AuthorizeQuery = z.infer<typeof AuthorizeQuerySchema>;
