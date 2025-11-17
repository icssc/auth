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
        redirectUri: "https://antalmanac.com/auth", // TODO @KevinWu098
        tokenEndpointAuthMethod: "none",
        name: "AntAlmanac",
        allowedDomainPatterns: ["https://staging-*.antalmanac.com"],
    },
    "antalmanac-dev": {
        clientId: "antalmanac-dev",
        clientSecret: null,
        redirectUri: "http://localhost:5173/auth", // TODO @KevinWu098
        tokenEndpointAuthMethod: "none",
        name: "AntAlmanac Dev",
    },
    zotmeet: {
        clientId: "zotmeet",
        clientSecret: null,
        redirectUri: "https://zotmeet.com/auth/login/google/callback",
        tokenEndpointAuthMethod: "none",
        name: "ZotMeet",
        allowedDomainPatterns: ["https://staging-*.zotmeet.com"],
    },
    "zotmeet-dev": {
        clientId: "zotmeet-dev",
        clientSecret: null,
        redirectUri: "http://localhost:3000/auth/login/google/callback",
        tokenEndpointAuthMethod: "none",
        name: "ZotMeet Dev",
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

/**
 * Check if a hostname matches a pattern with wildcards
 * Pattern: "staging-*.example.com" matches "staging-123.example.com"
 */
function matchesHostnamePattern(hostname: string, pattern: string): boolean {
    // Convert pattern to regex, escaping special chars except *
    const regexPattern = pattern
        .split(".")
        .map((part) => {
            if (part === "*") {
                return "[^.]+"; // Match any non-dot characters (at least one)
            }
            if (part.includes("*")) {
                // Handle patterns like "staging-*"
                // Replace * with .+ (one or more chars) instead of .* (zero or more)
                return part.replace(/\*/g, ".+");
            }
            // Escape special regex characters
            return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        })
        .join("\\.");

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(hostname);
}

export function isAllowedRedirectUrl(url: string): boolean {
    try {
        const parsedUrl = new URL(url);

        // Check exact redirect URI matches
        const exactMatch = Object.values(clients).some((client) => {
            const parsedAllowed = new URL(client.redirectUri);

            if (
                parsedUrl.protocol !== parsedAllowed.protocol ||
                parsedUrl.hostname !== parsedAllowed.hostname ||
                parsedUrl.port !== parsedAllowed.port
            ) {
                return false;
            }

            return parsedUrl.pathname.startsWith(parsedAllowed.pathname);
        });

        if (exactMatch) {
            return true;
        }

        // Check domain patterns with wildcards
        return Object.values(clients).some((client) => {
            if (!client.allowedDomainPatterns) {
                return false;
            }

            return client.allowedDomainPatterns.some((pattern) => {
                // Parse the pattern by replacing * with a placeholder for URL parsing
                const patternForParsing = pattern.replace(/\*/g, "wildcard");

                try {
                    const parsedPattern = new URL(patternForParsing);

                    // Extract the original pattern hostname (with wildcards)
                    const patternHostname = pattern
                        .replace(/^https?:\/\//, "")
                        .replace(/:\d+.*$/, "") // Remove port and path
                        .replace(/\/.*$/, ""); // Remove path

                    // Protocol must match exactly
                    if (parsedUrl.protocol !== parsedPattern.protocol) {
                        return false;
                    }

                    // Port must match exactly
                    if (parsedUrl.port !== parsedPattern.port) {
                        return false;
                    }

                    // Check hostname with wildcard matching
                    return matchesHostnamePattern(
                        parsedUrl.hostname,
                        patternHostname
                    );
                } catch {
                    return false;
                }
            });
        });
    } catch {
        return false;
    }
}
