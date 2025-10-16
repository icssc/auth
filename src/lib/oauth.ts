import { OAuth2Client } from "google-auth-library";

/**
 * Creates a configured Google OAuth2 client
 */
export function createGoogleOAuth2Client(
    env: CloudflareBindings
): OAuth2Client {
    return new OAuth2Client({
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        redirectUri: env.GOOGLE_REDIRECT_URI,
    });
}
