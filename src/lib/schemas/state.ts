import * as z from "zod";

const BaseStateInner = z.object({
    client_id: z.string(),
    redirect_uri: z.string(),
    state: z.string().optional(),
    code_challenge: z.string(),
    scope: z.string(),
});

const GoogleStateInner = BaseStateInner.extend({
    provider: z.literal("google"),
    code_verifier: z.string(),
});

const AppleStateInner = BaseStateInner.extend({
    provider: z.literal("apple"),
});

export const StateInnerSchema = z.discriminatedUnion("provider", [
    GoogleStateInner,
    AppleStateInner,
]);

export type StateInner = z.infer<typeof StateInnerSchema>;

export const StateDataSchema = z.object({
    digest: z.string(),
    inner: StateInnerSchema,
});

export type StateData = z.infer<typeof StateDataSchema>;
