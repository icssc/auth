import { Hono } from "hono";
import apple from "@/routes/callback/apple";
import google from "@/routes/callback/google";

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.route("/google", google);
app.route("/apple", apple);

export default app;
