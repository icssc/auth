import { cors } from "hono/cors";
import { isAllowedRedirectUrl } from "@/lib/clients/validate";

export const registeredClientCors = cors({
    origin: (origin) => (origin && isAllowedRedirectUrl(origin) ? origin : ""),
    allowMethods: ["GET", "POST", "OPTIONS"],
    credentials: true,
});
