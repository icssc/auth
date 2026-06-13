import * as z from "zod";

const BaseSession = z.object({
    user_id: z.string(),
    email: z.string(),
    name: z.string(),
    picture: z.string().optional(),
    scope: z.string(),
});

const GoogleSession = BaseSession.extend({
    provider: z.literal("google"),
    google_access_token: z.string().optional(),
    google_refresh_token: z.string().optional(),
    google_token_expiry: z.number().optional(),
});

const AppleSession = BaseSession.extend({
    provider: z.literal("apple"),
});

export const SessionSchema = z.discriminatedUnion("provider", [
    GoogleSession,
    AppleSession,
]);

export type Session = z.infer<typeof SessionSchema>;
