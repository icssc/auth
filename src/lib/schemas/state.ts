import * as z from "zod";

export const StateDataSchema = z.object({
    client_id: z.string(),
    redirect_uri: z.string(),
    state: z.string().optional(),
    code_challenge: z.string(),
    scope: z.string(),
});

export type StateData = z.infer<typeof StateDataSchema>;
