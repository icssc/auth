/**
 * ICSSC Auth SSO Client
 *
 * This module provides automatic session synchronization across ICSSC apps.
 * When a user signs into one app (e.g., AntAlmanac), they'll be automatically
 * signed into other apps (e.g., PeterPortal) without clicking "Sign In".
 *
 * Usage in your app:
 *
 * ```typescript
 * import { checkIcsscSession, autoSignIn } from '@icssc/auth/sso-client';
 *
 * // Check if user has an active ICSSC session
 * const session = await checkIcsscSession();
 * if (session.valid && !isLoggedIn) {
 *   // Auto-trigger sign in
 *   await signIn('icssc');
 * }
 *
 * // Or use the helper that does both:
 * autoSignIn({
 *   isLoggedIn: () => !!session,
 *   triggerSignIn: () => signIn('icssc'),
 * });
 * ```
 */

export interface IcsscUser {
    id: string;
    email: string;
    name: string;
    picture?: string;
}

export interface SessionCheckResult {
    valid: boolean;
    user: IcsscUser | null;
}

const AUTH_ORIGIN = "https://auth.icssc.club";
const SESSION_CHECK_TIMEOUT = 5000; // 5 seconds

/**
 * Check if there's an active session on auth.icssc.club using a hidden iframe.
 * This works even with third-party cookie restrictions.
 */
export function checkIcsscSession(): Promise<SessionCheckResult> {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => {
            cleanup();
            resolve({ valid: false, user: null });
        }, SESSION_CHECK_TIMEOUT);

        const iframe = document.createElement("iframe");
        iframe.style.display = "none";
        iframe.src = `${AUTH_ORIGIN}/session/check?origin=${encodeURIComponent(window.location.origin)}`;

        const handleMessage = (event: MessageEvent) => {
            if (event.origin !== AUTH_ORIGIN) return;
            if (event.data?.type !== "icssc-session-check") return;

            cleanup();
            resolve({
                valid: event.data.valid,
                user: event.data.user,
            });
        };

        const cleanup = () => {
            clearTimeout(timeout);
            window.removeEventListener("message", handleMessage);
            if (iframe.parentNode) {
                iframe.parentNode.removeChild(iframe);
            }
        };

        window.addEventListener("message", handleMessage);
        document.body.appendChild(iframe);
    });
}

export interface AutoSignInOptions {
    /** Function that returns true if user is already logged in locally */
    isLoggedIn: () => boolean;
    /** Function to trigger the sign-in flow (e.g., NextAuth's signIn('icssc')) */
    triggerSignIn: () => void | Promise<void>;
    /** Optional callback when session check completes */
    onSessionCheck?: (result: SessionCheckResult) => void;
    /** Delay before checking (ms). Default: 100 */
    delay?: number;
}

/**
 * Automatically sign in the user if they have an active ICSSC session
 * but aren't logged in locally.
 *
 * Call this on app load/mount.
 */
export async function autoSignIn(options: AutoSignInOptions): Promise<void> {
    const { isLoggedIn, triggerSignIn, onSessionCheck, delay = 100 } = options;

    // Small delay to let the app initialize
    await new Promise((resolve) => setTimeout(resolve, delay));

    // Skip if already logged in
    if (isLoggedIn()) {
        return;
    }

    // Check for ICSSC session
    const result = await checkIcsscSession();
    onSessionCheck?.(result);

    // If there's a valid session on auth.icssc.club but user isn't logged in locally,
    // trigger sign in (this will be instant since session exists)
    if (result.valid && !isLoggedIn()) {
        await triggerSignIn();
    }
}

/**
 * React hook for automatic SSO (for React apps)
 *
 * Usage:
 * ```tsx
 * function App() {
 *   const { data: session, status } = useSession();
 *
 *   useIcsscAutoSignIn({
 *     isLoggedIn: () => status === 'authenticated',
 *     triggerSignIn: () => signIn('icssc'),
 *     enabled: status !== 'loading', // wait for session check to complete
 *   });
 *
 *   return <div>...</div>;
 * }
 * ```
 */
export interface UseAutoSignInOptions extends Omit<
    AutoSignInOptions,
    "isLoggedIn" | "triggerSignIn"
> {
    isLoggedIn: () => boolean;
    triggerSignIn: () => void | Promise<void>;
    /** Whether to enable auto sign in. Default: true */
    enabled?: boolean;
}

// Note: This is a plain function that can be called in useEffect
// We don't include React as a dependency here
export function createAutoSignInEffect(options: UseAutoSignInOptions) {
    const { enabled = true, ...autoSignInOptions } = options;

    if (!enabled) return () => {};

    let cancelled = false;

    autoSignIn({
        ...autoSignInOptions,
        triggerSignIn: async () => {
            if (!cancelled) {
                await autoSignInOptions.triggerSignIn();
            }
        },
    });

    return () => {
        cancelled = true;
    };
}
