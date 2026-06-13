import * as z from "zod";

export const AppleUserSchema = z.object({
    name: z
        .object({
            firstName: z.string().optional(),
            lastName: z.string().optional(),
        })
        .optional(),
    email: z.string().optional(),
});

export type AppleUser = z.infer<typeof AppleUserSchema>;

export const AppleProfileSchema = z.object({
    name: z.string(),
    email: z.string(),
});

export type AppleProfile = z.infer<typeof AppleProfileSchema>;
