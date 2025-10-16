import { Hono } from "hono";
import google from "@/routes/callback/google";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.route("/google", google);

export default app;
