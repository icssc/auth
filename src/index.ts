import { Hono } from "hono";
import { getDb } from "./db";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.get("/", (c) => {
    const db = getDb(c.env.AUTH_DB);

    return c.text("Hello Hono!");
});

export default app;
