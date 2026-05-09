import { Google } from "arctic";

export function createGoogleClient(env: CloudflareBindings): Google {
    return new Google(
        env.GOOGLE_CLIENT_ID,
        env.GOOGLE_CLIENT_SECRET,
        env.GOOGLE_REDIRECT_URI
    );
}
