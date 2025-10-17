import * as z from "zod";

export const ClientSchema = z.object({
    clientId: z.string(),
    clientSecret: z.string().nullable(),
    redirectUri: z.string(),
    tokenEndpointAuthMethod: z.enum(["none", "client_secret_basic"]),
    name: z.string(),
});

export type Client = z.infer<typeof ClientSchema>;

export const clients: Record<string, Client> = {
    antalmanac: {
        clientId: "antalmanac",
        clientSecret: null,
        redirectUri: "https://antalmanac.com/auth", // TODO @KevinWu098
        tokenEndpointAuthMethod: "none",
        name: "AntAlmanac",
    },
};

/**
 * Get a client by client ID
 */
export function getClient(clientId: string): Client | undefined {
    return clients[clientId];
}

/**
 * Validate client credentials
 */
export function validateClient(
    clientId: string,
    redirectUri: string
): Client | null {
    const client = getClient(clientId);
    if (!client) {
        return null;
    }

    if (client.redirectUri !== redirectUri) {
        return null;
    }

    return client;
}
