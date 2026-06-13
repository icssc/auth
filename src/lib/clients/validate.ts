import { type Client, clients } from "@/lib/clients/clients";
import {
    matchesPostLogoutOrigin,
    matchesRedirectUri,
} from "@/lib/clients/patterns";

export function validateClient(
    clientId: string,
    redirectUri: string
): Client | null {
    const client = clients[clientId];
    if (!client || !matchesRedirectUri(redirectUri, client.redirectUris)) {
        return null;
    }
    return client;
}

export function isAllowedRedirectUrl(url: string): boolean {
    return Object.values(clients).some((client) =>
        matchesPostLogoutOrigin(url, client.postLogoutOrigins)
    );
}

export type { Client } from "@/lib/clients/clients";
