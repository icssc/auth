import type * as z from "zod";
import { tryCatchSync } from "@/lib/try-catch";

/**
 * Safely parse a JSON string and validate it against a Zod schema.
 *
 * Returns the parsed/validated data on success, or `null` if the input is
 * not valid JSON or does not match the schema. This guards against both
 * `JSON.parse` throwing on malformed input and schema mismatches.
 */
export function parseJsonWithSchema<T>(
    schema: z.ZodType<T>,
    raw: string
): T | null {
    const { data, error } = tryCatchSync(() => JSON.parse(raw));
    if (error) {
        return null;
    }

    const parsed = schema.safeParse(data);
    return parsed.success ? parsed.data : null;
}
