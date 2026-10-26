# druvc.com gatekeeper — setup (Dr. UVC LLC)

What it does: free pages stay public; /premium/* is served from a PRIVATE Cloudflare R2 bucket only to
(a) signed-in readers with an active Stripe subscription (Substack paid or druvc.com), or
(b) anyone holding a valid access code (expiry and use limit set per code).
Sign-in = one-time email link (no passwords). Every sign-in email lands on the list (export: /admin/list.csv).
Premium pages carry a "Licensed to <email>" watermark; views are rate-limited; AI/search robots told noindex/noai.

Tested locally 10/26/26: no-login -> blocked; code redeem -> access + watermark; code use-limit enforced;
email link -> sign-in, single use; signed-in free user -> "subscribe" page; list export; admin key required;
open-redirect blocked. NOT yet tested: the live Stripe paid check (needs UV's key).

## UV's one-time steps (credentials stay with UV; Claude never sees them)
1. Stripe -> Developers -> API keys -> Create restricted key: Customers = Read, Subscriptions = Read (nothing else).
   If math and investing use two Stripe accounts, make one key in each.
2. Resend.com (free, 3,000 emails/month) -> sign up -> add domain druvc.com -> add the DNS records it shows
   in Cloudflare -> create an API key. (Sends the sign-in emails from signin@druvc.com.)
3. Cloudflare -> Workers -> druvc-gate -> Settings -> Variables and Secrets -> add as SECRET:
   STRIPE_KEYS (the key(s), comma-separated), RESEND_KEY, ADMIN_KEY (any long random phrase).
4. Cloudflare -> Security -> Bots -> turn on "Block AI bots" and "Bot Fight Mode" for druvc.com.

## Claude's steps (with UV's OK)
- Create KV namespace "druvc-gate" and private R2 bucket "druvc-premium"; put the KV id in wrangler.toml.
- Deploy to the test address druvc-gate.<account>.workers.dev; UV tries every path.
- Go live: add route druvc.com/* (requires druvc.com DNS on Cloudflare, proxied).
- Premium pages are uploaded to R2 only — never to the public GitHub repo.

## Making codes (UV or Claude)
POST /admin/code with header "Authorization: Bearer <ADMIN_KEY>" and JSON
{"code":"ADVISOR-NOV","days":7,"uses":3,"scope":"/premium/","note":"advisor trial"}
