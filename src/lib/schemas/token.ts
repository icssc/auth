import * as z from "zod";

// Authorization Code Grant
const AuthorizationCodeGrantSchema = z.object({
    grant_type: z.literal("authorization_code"),
    code: z.string(),
    redirect_uri: z.string().url(),
    client_id: z.string().optional(),
    code_verifier: z.string(),
});

// Refresh Token Grant
const RefreshTokenGrantSchema = z.object({
    grant_type: z.literal("refresh_token"),
    refresh_token: z.string(),
    client_id: z.string().optional(),
});

// Union of both grant types
export const TokenRequestSchema = z.discriminatedUnion("grant_type", [
    AuthorizationCodeGrantSchema,
    RefreshTokenGrantSchema,
]);

export type TokenRequest = z.infer<typeof TokenRequestSchema>;
