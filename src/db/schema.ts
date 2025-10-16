import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

// OAuth Clients
export const clients = sqliteTable("clients", {
    clientId: text("client_id").primaryKey(),
    clientSecret: text("client_secret"), // nullable for public clients
    redirectUri: text("redirect_uri").notNull(),
    tokenEndpointAuthMethod: text("token_endpoint_auth_method")
        .notNull()
        .default("none"), // 'none' or 'client_secret_basic'
    name: text("name"),
    createdAt: integer("created_at", { mode: "timestamp" })
        .notNull()
        .$defaultFn(() => new Date()),
});

// Users
export const users = sqliteTable("users", {
    id: text("id").primaryKey(),
    pwSha256: text("pw_sha256"), // nullable for federated IDs
    name: text("name").notNull(),
    email: text("email").notNull().unique(),
    createdAt: integer("created_at", { mode: "timestamp" })
        .notNull()
        .$defaultFn(() => new Date()),
    updatedAt: integer("updated_at", { mode: "timestamp" })
        .notNull()
        .$defaultFn(() => new Date()),
});

// Sessions
export const sessions = sqliteTable("sessions", {
    id: text("id").primaryKey(),
    userId: text("user_id")
        .notNull()
        .references(() => users.id, { onDelete: "cascade" }),
    expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
    createdAt: integer("created_at", { mode: "timestamp" })
        .notNull()
        .$defaultFn(() => new Date()),
});
