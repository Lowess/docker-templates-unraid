# Unraid Template Sync

`unraid-template-sync` receives GitHub push webhooks, updates the mounted
`docker-templates-unraid` checkout, and mirrors its top-level `Lowess/*.xml`
files into the Community Applications private template directory.

The service is deliberately narrow:

- GitHub webhook HMAC-SHA256 validation is mandatory.
- Only `push` events for the configured repository and branch start a sync.
- GitHub webhook source CIDRs are loaded from `https://api.github.com/meta`,
  cached in `/data`, and refreshed every six hours.
- `X-Forwarded-For` is used only when the direct peer belongs to a configured
  trusted proxy CIDR.
- Sync work runs asynchronously so GitHub receives a prompt `202` response.
- A startup sync catches changes missed while the container was stopped.

## Build and publish

The Unraid template expects `ghcr.io/lowess/unraid-template-sync:latest`.
Build the image from this directory and publish it to that package before the
first catalog installation:

```bash
docker build -t ghcr.io/lowess/unraid-template-sync:latest .
docker push ghcr.io/lowess/unraid-template-sync:latest
```

The package must be public so Unraid can pull it without registry credentials.

## Bootstrap on Unraid

1. Run the old sync script once more, or install
   `Lowess/unraid-template-sync.xml` directly by its raw GitHub URL.
2. Deploy **Unraid Template Sync** from Community Applications.
3. Generate a high-entropy secret, for example:

   ```bash
   openssl rand -hex 32
   ```

4. Put the same value in the container's **GitHub Webhook Secret** field and
   the GitHub repository webhook's **Secret** field.
5. In GitHub, set the payload URL to
   `https://YOUR-WEBHOOK-HOST/webhook`, content type to `application/json`,
   and subscribe only to **push** events.

No GitHub token or SSH key is needed because the configured repository is
public and the container fetches it over HTTPS.

## Nginx Proxy Manager

Proxy the public HTTPS hostname to the container's port `9000` on their shared
Docker network, or to the Unraid host and mapped port `9141`. Do not enable a
Pomerium or browser-login flow for this host; GitHub cannot complete it.

Create an NPM Access List containing the current CIDRs in GitHub's `hooks`
metadata field and deny every other source. The current Nginx directives can
be printed from the image:

```bash
docker exec Unraid-Template-Sync \
  python /app/sync_service.py --print-nginx-allowlist
```

GitHub changes these ranges occasionally, so refresh the NPM list periodically.
The application independently refreshes and enforces the ranges, but the NPM
list remains a useful outer layer. HMAC validation remains mandatory because
IP ranges alone do not authenticate a webhook for this repository.

`TRUSTED_PROXY_CIDRS` must include the address range from which NPM connects to
the service. Its default, `172.16.0.0/12`, covers common Docker bridge networks.
If NPM is elsewhere, narrow or replace this setting with NPM's actual address
or subnet. A wrong value fails closed: NPM's address will not match a GitHub
hook range and the webhook will receive `403`.

## Behavior and endpoints

- `POST /webhook` validates and queues eligible GitHub pushes.
- `GET /healthz` reports the last sync result and hook-range refresh status.
- The destination mirror deletes stale `.xml` files but leaves non-XML files
  untouched.
- `GIT_CLEAN=true` preserves the old script's behavior and removes untracked
  files from the mounted checkout. Set it to `false` only if that checkout is
  intentionally used for local files.

The service intentionally mounts only the repository checkout and private
template destination, does not use the Docker socket, and does not run in
privileged mode.

## Local tests

```bash
python -m unittest discover -s tests -v
```
