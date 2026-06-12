export type Origin = {
    protocol: "http:" | "https:";
    port: string;
    labels: readonly string[];
};

export type RedirectUri = Origin & {
    pathname: string;
};

export function parseHost(host: string): Origin {
    const protocol = host.startsWith("https://")
        ? "https:"
        : host.startsWith("http://")
          ? "http:"
          : null;
    if (!protocol) {
        throw new Error(`invalid host: ${host}`);
    }
    const rest = host.slice(protocol.length + 2);
    const slash = rest.indexOf("/");
    const authority = slash === -1 ? rest : rest.slice(0, slash);
    const colon = authority.lastIndexOf(":");
    const maybePort = colon === -1 ? "" : authority.slice(colon + 1);
    const hasPort = colon !== -1 && /^\d+$/.test(maybePort);
    const hostname = hasPort ? authority.slice(0, colon) : authority;
    return {
        protocol,
        port: hasPort ? maybePort : "",
        labels: hostname.split("."),
    };
}

export function compileRedirect(host: string, pathname: string): RedirectUri {
    return { ...parseHost(host), pathname };
}

function labelMatches(label: string, pattern: string): boolean {
    if (!pattern.includes("*")) {
        return label === pattern;
    }
    if (pattern === "*") {
        return label.length > 0;
    }
    if (pattern.endsWith("*") && !pattern.slice(0, -1).includes("*")) {
        const prefix = pattern.slice(0, -1);
        return label.startsWith(prefix) && label.length > prefix.length;
    }
    return false;
}

function originMatches(url: URL, origin: Origin): boolean {
    const labels = url.hostname.split(".");
    return (
        url.protocol === origin.protocol &&
        url.port === origin.port &&
        labels.length === origin.labels.length &&
        origin.labels.every((pattern, i) => labelMatches(labels[i]!, pattern))
    );
}

export function matchesRedirectUri(
    url: string,
    allowed: readonly RedirectUri[]
): boolean {
    try {
        const parsed = new URL(url);
        return allowed.some(
            (entry) =>
                originMatches(parsed, entry) &&
                parsed.pathname === entry.pathname
        );
    } catch {
        return false;
    }
}

export function matchesPostLogoutOrigin(
    url: string,
    allowed: readonly Origin[]
): boolean {
    try {
        const parsed = new URL(url);
        return allowed.some((entry) => originMatches(parsed, entry));
    } catch {
        return false;
    }
}
