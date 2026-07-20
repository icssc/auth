# auth.icssc.club

A minimal OIDC implementation on Hono and Cloudflare (Workers, KV)

## Usage by Projects
ICSSC Projects relies on auth.icssc.club to centralize Google and Apple auth.

If a new project needs to start using auth, it must be added to the list of allowed clients in `clients.ts`.

## Local setup

### When you should run locally
When contributing to our projects, you typically only need to use the official deploy at auth.icssc.club. You will only need to set this up locally if you are:
1. Contributing to this repo
2. Working on a project locally with a host that's not allowed in `clients.ts`. This is almost never the case.

### Initial setup
As the setup steps will make changes to tracked files, consider making a new local branch first so you don't lose your changes.
1. Run `pnpm i`. You will need to accept builds
2. Copy `.dev.vars.example` to `.dev.vars`
3. Run locally: `pnpm dev -- --local`. Without the local flag, wrangler will assume you're trying to run this on Cloudflare.
    - You most likely will have to set up Google or Apple auth (see below) to actually test anything

### Setting up Google Auth
1. Create your own Google client with a personal account in the [cloud console](https://cloud.google.com/cloud-console)
    - Instructions are [available online](https://support.google.com/cloud/answer/15544987?hl=en)
    - Be sure to save the credentials given to your project (client ID and secret)
2. Update `wrangler.jsonc`
    - Replace any mention of `https://auth.icssc.club` with `http://localhost:8787`
    - Update `GOOGLE_CLIENT_ID` to be yours
3. Update `.dev.vars`
    - Update `GOOGLE_CLIENT_SECRET` to be yours
    - Generate an HMAC key for `STATE_SIGNING_SECRET`

### Troubleshooting
When initially running, you may find that `KvNamespace` is empty, causing an error in the POST `/token` route.
- To fix this, simply go to `http://localhost:8787/jwks.json` in your browser, which will seed `AUTH_KV_KEYS`
