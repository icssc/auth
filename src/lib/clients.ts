import * as z from "zod";

export const ClientSchema = z.object({
    clientId: z.string(),
    clientSecret: z.string().nullable(),
    redirectUri: z.string(),
    tokenEndpointAuthMethod: z.enum(["none", "client_secret_basic"]),
    name: z.string(),
    allowedDomainPatterns: z.array(z.string()).optional(),
});

export type Client = z.infer<typeof ClientSchema>;

export const clients: Record<string, Client> = {
    antalmanac: {
        clientId: "antalmanac",
        clientSecret: null,
        redirectUri: "https://antalmanac.com/auth",
        tokenEndpointAuthMethod: "none",
        name: "AntAlmanac",
        allowedDomainPatterns: [
            "https://antalmanac.com",
            "https://staging-*.antalmanac.com",
        ],
    },
    "antalmanac-dev": {
        clientId: "antalmanac-dev",
        clientSecret: null,
        redirectUri: "http://localhost:5173/auth",
        tokenEndpointAuthMethod: "none",
        name: "AntAlmanac Dev",
        allowedDomainPatterns: ["http://localhost:5173"],
    },
    peterportal: {
        clientId: "peterportal",
        clientSecret: null,
        redirectUri: "https://peterportal.com/api/users/auth/google/callback",
        tokenEndpointAuthMethod: "none",
        name: "PeterPortal",
        allowedDomainPatterns: [
            "https://peterportal.org",
            "https://staging-*.peterportal.org",
        ],
    },
    "peterportal-dev": {
        clientId: "peterportal-dev",
        clientSecret: null,
        redirectUri: "http://localhost:8080/api/users/auth/google/callback",
        tokenEndpointAuthMethod: "none",
        name: "PeterPortal Dev",
        allowedDomainPatterns: ["http://localhost:8080", "http://localhost:3000"],
    },
    zotmeet: {
        clientId: "zotmeet",
        clientSecret: null,
        redirectUri: "https://zotmeet.com/auth/login/google/callback",
        tokenEndpointAuthMethod: "none",
        name: "ZotMeet",
        allowedDomainPatterns: [
            "https://zotmeet.com",
            "https://staging-*.zotmeet.com",
        ],
    },
    "zotmeet-dev": {
        clientId: "zotmeet-dev",
        clientSecret: null,
        redirectUri: "http://localhost:3000/auth/login/google/callback",
        tokenEndpointAuthMethod: "none",
        name: "ZotMeet Dev",
        allowedDomainPatterns: ["http://localhost:3000"],
    },
    test: {
        clientId: "test",
        clientSecret: null,
        redirectUri: "http://localhost:3000/auth",
        tokenEndpointAuthMethod: "none",
        name: "Test",
        allowedDomainPatterns: ["http://localhost:3000"],
    },
};

/**
 * Get a client by client ID
 */
export function getClient(clientId: string): Client | undefined {
    return clients[clientId];
}

/**
 * Check if a hostname matches a pattern with wildcards
 * Pattern: "staging-*.example.com" matches "staging-123.example.com"
 */
function matchesHostnamePattern(hostname: string, pattern: string): boolean {
    const regexPattern = pattern
        .split(".")
        .map((part) => {
            if (part === "*") {
                return "[^.]+";
            }
            if (part.includes("*")) {
                return part.replace(/\*/g, ".+");
            }
            return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        })
        .join("\\.");

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(hostname);
}

/**
 * Check if a URL matches an exact redirect URI
 */
function matchesExactRedirectUri(parsedUrl: URL, redirectUri: string): boolean {
    try {
        const parsedRedirect = new URL(redirectUri);
        return (
            parsedUrl.protocol === parsedRedirect.protocol &&
            parsedUrl.hostname === parsedRedirect.hostname &&
            parsedUrl.port === parsedRedirect.port &&
            parsedUrl.pathname.startsWith(parsedRedirect.pathname)
        );
    } catch {
        return false;
    }
}

/**
 * Check if a URL matches any of the given wildcard domain patterns
 */
function matchesDomainPattern(parsedUrl: URL, pattern: string): boolean {
    const patternForParsing = pattern.replace(/\*/g, "wildcard");

    try {
        const parsedPattern = new URL(patternForParsing);
        const patternHostname = pattern
            .replace(/^https?:\/\//, "")
            .replace(/:\d+.*$/, "")
            .replace(/\/.*$/, "");

        return (
            parsedUrl.protocol === parsedPattern.protocol &&
            parsedUrl.port === parsedPattern.port &&
            matchesHostnamePattern(parsedUrl.hostname, patternHostname)
        );
    } catch {
        return false;
    }
}

/**
 * Check if a redirect URI is allowed for a specific client
 */
function isRedirectUriAllowedForClient(
    client: Client,
    redirectUri: string
): boolean {
    try {
        const parsedUrl = new URL(redirectUri);

        // Check exact match first
        if (matchesExactRedirectUri(parsedUrl, client.redirectUri)) {
            return true;
        }

        // Check against allowed domain patterns
        if (client.allowedDomainPatterns) {
            return client.allowedDomainPatterns.some((pattern) =>
                matchesDomainPattern(parsedUrl, pattern)
            );
        }

        return false;
    } catch {
        return false;
    }
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

    if (!isRedirectUriAllowedForClient(client, redirectUri)) {
        return null;
    }

    return client;
}

/**
 * Check if a redirect URL is allowed for any registered client
 * Used by logout endpoint to prevent open redirect vulnerabilities
 */
export function isAllowedRedirectUrl(url: string): boolean {
    try {
        const parsedUrl = new URL(url);

        // Check if URL matches any client's configuration
        return Object.values(clients).some((client) => {
            // Check exact redirect URI match
            if (matchesExactRedirectUri(parsedUrl, client.redirectUri)) {
                return true;
            }

            // Check domain patterns
            if (client.allowedDomainPatterns) {
                return client.allowedDomainPatterns.some((pattern) =>
                    matchesDomainPattern(parsedUrl, pattern)
                );
            }

            return false;
        });
    } catch {
        return false;
    }
}
