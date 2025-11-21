import * as z from "zod";

export const AuthCodeSchema = z.object({
    user_id: z.string(),
    email: z.string(),
    name: z.string(),
    picture: z.string().optional(),
    client_id: z.string(),
    redirect_uri: z.string(),
    code_challenge: z.string(),
    scope: z.string(),
    created_at: z.number(),
    // Google OAuth tokens for accessing Google APIs
    google_access_token: z.string().optional(),
    google_refresh_token: z.string().optional(),
    google_token_expiry: z.number().optional(), // Unix timestamp in milliseconds
});

export type AuthCode = z.infer<typeof AuthCodeSchema>;
