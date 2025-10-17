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
    "antalmanac-dev": {
        clientId: "antalmanac-dev",
        clientSecret: null,
        redirectUri: "http://localhost:5173/auth", // TODO @KevinWu098
        tokenEndpointAuthMethod: "none",
        name: "AntAlmanac Dev",
    },
    "test-client-id": {
        clientId: "test-client-id",
        clientSecret: null,
        redirectUri: "http://localhost:3000/api/auth/callback/icssc",
        tokenEndpointAuthMethod: "none",
        name: "Next.js Test Client",
    },
    "test-client-two-id": {
        clientId: "test-client-two-id",
        clientSecret: null,
        redirectUri: "http://localhost:3001/api/auth/callback/icssc",
        tokenEndpointAuthMethod: "none",
        name: "Next.js Test Client #2",
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
