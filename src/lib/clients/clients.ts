import {
    compileRedirect,
    type Origin,
    parseHost,
    type RedirectUri,
} from "@/lib/clients/patterns";

export type Client = {
    clientId: string;
    redirectUris: readonly RedirectUri[];
    postLogoutOrigins: readonly Origin[];
};

function register({
    clientId,
    hosts,
    oauthPaths,
}: {
    clientId: string;
    hosts: readonly string[];
    oauthPaths: readonly string[];
}): Client {
    return {
        clientId,
        redirectUris: hosts.flatMap((host) =>
            oauthPaths.map((path) => compileRedirect(host, path))
        ),
        postLogoutOrigins: hosts.map(parseHost),
    };
}

export const clients: Record<string, Client> = {
    antalmanac: register({
        clientId: "antalmanac",
        hosts: [
            "https://antalmanac.com",
            "https://www.antalmanac.com",
            "https://staging-shared.antalmanac.com",
            "https://scheduler-*.antalmanac.com",
            "https://staging-*.antalmanac.com",
        ],
        oauthPaths: ["/api/auth/oauth2/callback/icssc"],
    }),
    "antalmanac-dev": register({
        clientId: "antalmanac-dev",
        hosts: ["http://localhost:3000"],
        oauthPaths: ["/api/auth/oauth2/callback/icssc"],
    }),
    peterportal: register({
        clientId: "peterportal",
        hosts: [
            "https://antalmanac.com",
            "https://www.antalmanac.com",
            "https://staging-shared.antalmanac.com",
            "https://planner-*.antalmanac.com",
            "https://staging-*.antalmanac.com",
        ],
        oauthPaths: [
            "/planner/api/users/auth/google/callback",
            "/planner/api/users/auth/google/callback/native",
        ],
    }),
    "peterportal-dev": register({
        clientId: "peterportal-dev",
        hosts: ["http://localhost:8080", "http://localhost:3000"],
        oauthPaths: [
            "/planner/api/users/auth/google/callback",
            "/planner/api/users/auth/google/callback/native",
        ],
    }),
    peterplate: register({
        clientId: "peterplate",
        hosts: ["https://peterplate.com", "https://staging-*.peterplate.com"],
        oauthPaths: ["/api/auth/oauth2/callback/icssc"],
    }),
    "peterplate-dev": register({
        clientId: "peterplate-dev",
        hosts: ["http://localhost:3000"],
        oauthPaths: ["/api/auth/oauth2/callback/icssc"],
    }),
    zotmeet: register({
        clientId: "zotmeet",
        hosts: [
            "https://zotmeet.com",
            "https://staging.zotmeet.com",
            "https://staging-*.zotmeet.com",
        ],
        oauthPaths: [
            "/auth/login/google/callback",
            "/auth/login/google/callback/native",
            "/auth/login/apple/callback",
            "/auth/login/apple/callback/native",
        ],
    }),
    "zotmeet-dev": register({
        clientId: "zotmeet-dev",
        hosts: ["http://localhost:3000"],
        oauthPaths: [
            "/auth/login/google/callback",
            "/auth/login/google/callback/native",
            "/auth/login/apple/callback",
            "/auth/login/apple/callback/native",
        ],
    }),
    test: register({
        clientId: "test",
        hosts: ["http://localhost:3000"],
        oauthPaths: ["/auth"],
    }),
    zotnfound: register({
        clientId: "zotnfound",
        hosts: ["https://zotnfound.com", "https://www.zotnfound.com"],
        oauthPaths: ["/api/auth/callback"],
    }),
    "zotnfound-clone": register({
        clientId: "zotnfound-clone",
        hosts: [
            "https://clone.zotnfound.com",
            "https://staging-*.zotnfound.com",
        ],
        oauthPaths: ["/api/auth/callback"],
    }),
    "zotnfound-dev": register({
        clientId: "zotnfound-dev",
        hosts: ["http://localhost:3000"],
        oauthPaths: ["/api/auth/callback"],
    }),
    "anteater-api-key-manager": register({
        clientId: "anteater-api-key-manager",
        hosts: [
            "https://dashboard.anteaterapi.com",
            "https://*.dashboard.anteaterapi.com",
        ],
        oauthPaths: ["/api/auth/callback/icssc"],
    }),
    "anteater-api-key-manager-dev": register({
        clientId: "anteater-api-key-manager-dev",
        hosts: ["http://localhost:3000"],
        oauthPaths: ["/api/auth/callback/icssc"],
    }),
};
