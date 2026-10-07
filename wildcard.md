# Wildcard certificates (`*.example.com`)

A wildcard certificate covers a zone and every subdomain directly below it, such as `example.com`, `cloud.example.com` and `git.example.com`. After you issue it once, any new subdomain you add in pve-gateway is on HTTPS immediately, with no per-domain certificate request.

## How it works

Let's Encrypt only issues wildcard certificates through the **DNS-01** challenge. certbot proves you control the domain by creating a temporary `_acme-challenge` TXT record through your DNS provider's API, which is why pve-gateway needs an API token for your DNS provider.

- Port 80 doesn't need to be reachable from the internet to *issue* the certificate. Visitors still reach your sites on port 443, though.
- One certificate covers **two names**: `example.com` and `*.example.com`.
- A wildcard covers **one level only**:

  | Name | Covered by `*.example.com`? |
  |---|---|
  | `example.com` | yes |
  | `cloud.example.com` | yes |
  | `a.b.example.com` | **no**: add a separate wildcard for `b.example.com` |

## 1. Point DNS at your Proxmox host

At your DNS provider, create two records pointing to the host's public IP:

| Type | Name | Value |
|---|---|---|
| A | `example.com` (or `@`) | your public IP |
| A | `*.example.com` (or `*`) | your public IP |

The wildcard A record means new subdomains resolve without any further DNS changes.

If the Proxmox host is behind a router, forward **TCP 443** to it (and **TCP 80** if you want HTTP → HTTPS redirects).

> **Cloudflare users:** set both records to **DNS only** (grey cloud). If they're proxied (orange cloud), Cloudflare terminates TLS itself and your certificate is never used.

## 2. Install the certbot DNS plugin

On the Proxmox host, install nginx and certbot if you haven't already:

```bash
sh install.sh --with-nginx
```

Then install the plugin for your DNS provider:

| Provider | Install |
|---|---|
| Cloudflare | `apt install python3-certbot-dns-cloudflare` |
| DigitalOcean | `apt install python3-certbot-dns-digitalocean` |
| Linode / Akamai | `apt install python3-certbot-dns-linode` |
| DNSimple | `apt install python3-certbot-dns-dnsimple` |
| OVH | `apt install python3-certbot-dns-ovh` |
| RFC 2136 (BIND, PowerDNS, Knot) | `apt install python3-certbot-dns-rfc2136` |

To check it's installed (it should be listed as `* dns-<provider>`):

```bash
certbot plugins
```

## 3. Create an API token

Give the token the **smallest** permission that lets it edit DNS records for the one zone.

### Cloudflare

1. Go to **My Profile → API Tokens → Create Token**.
2. Use the **Edit zone DNS** template.
3. Under **Zone Resources**, choose *Include → Specific zone → example.com*.
4. Create the token and copy it. Cloudflare shows it only once.

Use an **API token**, not the Global API Key.

### Other providers

| Provider | What to create |
|---|---|
| DigitalOcean | **API → Tokens → Generate New Token** with *write* scope |
| Linode / Akamai | **Profile → API Tokens** with *Domains: Read/Write* |
| DNSimple | **Account → Automation → API tokens** (account token) |
| OVH | Keys from https://api.ovh.com/createToken/ with `GET/POST/PUT/DELETE` on `/domain/zone/*`; endpoint usually `ovh-eu` |
| RFC 2136 | A TSIG key allowed to update the zone; enter the server IP, key name, secret and algorithm (default `HMAC-SHA512`) |

## 4. Add the wildcard in pve-gateway

1. Open the web UI → **Domains** tab → **Wildcard certificates → + Add wildcard**.
2. Fill in the form:
   - **Zone:** `example.com`. You can also type `*.example.com`; the `*.` is stripped.
   - **DNS provider:** pick yours. The credential fields change to match.
   - **Credentials:** paste the token.
   - **Propagation wait:** leave empty unless your provider's DNS is slow to update (then try `60`–`120` seconds).
   - **Let's Encrypt email:** optional, for expiry notices.
3. Click **Save & issue**.

The certificate is requested in the background and usually takes 30–60 seconds. The status goes from **issuing…** to **valid · 90d**.

To use the CLI instead:

```bash
pve-gateway cert '*.example.com'
```

## 5. Use it for your domains

For each domain (new or existing) under **Domains**:

- **HTTPS:** choose **Wildcard certificate (DNS)**.
- The form tells you which wildcard it will use, or warns you if none covers the name.

Save, and the domain is on HTTPS immediately.

## Renewal

certbot's systemd timer renews the certificate automatically about 30 days before expiry, using the same DNS plugin and stored credentials, and reloads nginx afterwards.

To check that renewal will work without changing anything:

```bash
certbot renew --dry-run --cert-name wildcard.example.com
```

To check expiry dates:

```bash
pve-gateway domains
```

The **Debug** tab warns when a certificate has fewer than 14 days left.

## Where things are stored

| What | Where |
|---|---|
| DNS credentials | `/etc/pve-gateway/dns/<id>.ini` (mode 0600, folder 0700) |
| Certificate | `/etc/letsencrypt/live/wildcard.example.com/` |
| nginx config | `/etc/nginx/conf.d/pve-gateway.conf` |

- **Credentials** are never shown again in the UI, the API or the debug report. When editing a wildcard, leave a credential field empty to keep the stored value. Deleting the wildcard deletes its credentials file.
- **Keep the credentials file in place:** certbot needs it for every renewal.
- **Certificate files** are kept even if you delete the wildcard in pve-gateway.
- **Rules:**
  - You can't delete or disable a wildcard while domains still use it. Switch those domains to another HTTPS option first.
  - The zone can't be changed after creation. Add a new wildcard instead.

## Troubleshooting

Click **Issue** (wildcard) or **Test** (domain) to see the exact error, or open the **Debug** tab.

| Error | Cause / fix |
|---|---|
| `certbot plugin dns-cloudflare is missing` | `apt install python3-certbot-dns-cloudflare` |
| `Error determining zone_id … Invalid request headers` | Cloudflare rejected the token: wrong or truncated, or it's a Global API Key. Create an **API token** as in step 3 and paste it again. |
| `Unable to determine zone identifier for …` | The token can't see that zone, or the zone name is wrong. Check *Zone Resources* includes it. |
| `Incorrect TXT record` / `NXDOMAIN looking up TXT` | DNS didn't update in time. Set **Propagation wait** to `60`–`120` and issue again. |
| `too many certificates already issued` | Let's Encrypt rate limit. Wait, and test with `certbot renew --dry-run` instead of repeated real requests. |
| Domain shows **no wildcard** | No enabled wildcard covers that name (remember: one level only). |
| Browser shows a Cloudflare certificate | The DNS record is proxied (orange cloud). Switch it to **DNS only**. |
| Works locally but not from outside | Router or firewall isn't forwarding TCP 443 to the host, or DNS points to the wrong IP. Domain **Test** shows what the name resolves to. |

## Trying it without a server

Mock mode simulates everything on your Mac, including a sample `*.example.com` wildcard used by `status.example.com`:

```bash
rm -rf .dev && ./dev.sh
```

Then open http://127.0.0.1:8099 and log in as `admin` / `admin`. In the mock:
- an API token of `bad` reproduces Cloudflare's invalid-credentials error
- zones ending in `.invalid` fail the zone lookup
- the OVH plugin is reported as not installed
