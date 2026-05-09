import { decodeBase64 } from "@oslojs/encoding";
import { Apple, Google } from "arctic";

export function createGoogleClient(env: CloudflareBindings): Google {
    return new Google(
        env.GOOGLE_CLIENT_ID,
        env.GOOGLE_CLIENT_SECRET,
        env.GOOGLE_REDIRECT_URI
    );
}

export function createAppleClient(env: CloudflareBindings): Apple {
    const base64 = env.APPLE_PRIVATE_KEY.replace(
        /-----BEGIN PRIVATE KEY-----/,
        ""
    )
        .replace(/-----END PRIVATE KEY-----/, "")
        .replace(/\s/g, "");
    const privateKey = decodeBase64(base64);
    return new Apple(
        env.APPLE_CLIENT_ID,
        env.APPLE_TEAM_ID,
        env.APPLE_KEY_ID,
        privateKey,
        env.APPLE_REDIRECT_URI
    );
}
