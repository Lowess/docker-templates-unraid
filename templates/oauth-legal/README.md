# Private Access Portal pages

Static public pages for a Google OAuth production consent screen. The site contains
no JavaScript, trackers, external assets, cookies, application inventory, or
infrastructure details.

## Before publishing

Replace every occurrence of `privacy@your-domain.example` with a working contact
address:

```sh
rg -l 'privacy@your-domain\.example' .
```

Serve this directory as the web root so the pages resolve as:

- `/` — application homepage
- `/privacy/` — privacy policy
- `/terms/` — terms of service

Use those exact HTTPS URLs in Google Auth Platform. Keep all three pages public and
do not place them behind the OAuth login they describe.

## Recommended Nginx response headers

Add these directives to the Nginx server or location that serves the pages:

```nginx
add_header Content-Security-Policy "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'" always;
add_header Referrer-Policy "no-referrer" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
```

`noindex` asks search engines not to list the pages; it is not access control. Google
must still be able to open the pages without authentication.
