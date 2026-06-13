import * as z from "zod";

const BaseAuthCode = z.object({
    user_id: z.string(),
    email: z.string(),
    name: z.string(),
    picture: z.string().optional(),
    client_id: z.string(),
    redirect_uri: z.string(),
    code_challenge: z.string(),
    scope: z.string(),
    nonce: z.string().optional(),
    created_at: z.number(),
});

const GoogleAuthCode = BaseAuthCode.extend({
    provider: z.literal("google"),
    google_access_token: z.string().optional(),
    google_refresh_token: z.string().optional(),
    google_token_expiry: z.number().optional(),
});

const AppleAuthCode = BaseAuthCode.extend({
    provider: z.literal("apple"),
});

export const AuthCodeSchema = z.discriminatedUnion("provider", [
    GoogleAuthCode,
    AppleAuthCode,
]);

export type AuthCode = z.infer<typeof AuthCodeSchema>;
