import * as z from "zod";

export const AuthCodeSchema = z.object({
    user_id: z.string(),
    email: z.string(),
    name: z.string(),
    client_id: z.string(),
    redirect_uri: z.string(),
    code_challenge: z.string(),
    scope: z.string(),
    created_at: z.number(),
});

export type AuthCode = z.infer<typeof AuthCodeSchema>;
