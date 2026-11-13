# docker-html2txt

[![Build, Test and Publish](https://github.com/clove3am/docker-html2txt/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/clove3am/docker-html2txt/actions/workflows/docker-publish.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small self-hosted web service that turns a public web page into plain text.
Give it a URL and it returns the readable text of that page, rendered by the
[Lynx](https://lynx.invisible-island.net/) text browser.

It is packaged as a tiny, multi-arch container image, and the URL handling is
hardened against Server-Side Request Forgery (SSRF) so it can safely be exposed
to other people.

## Features

- **Any public page to plain text** – headings, paragraphs, lists and tables are
  rendered as readable text; scripts, styles and images are dropped.
- **SSRF protection** – only `http`/`https` URLs are accepted, and every DNS
  answer and connection is checked so private, loopback, link-local (including
  cloud metadata endpoints) and reserved addresses are never reachable.
- **DNS rebinding safe** – addresses are validated at connect time, not just
  when the URL is parsed, so a hostname cannot change to an internal address
  between the check and the request.
- **Bounded resources** – request timeout, download size limit, redirect limit
  and a cap on concurrent conversions.
- **No JavaScript, no cookies** – pages are fetched statelessly and rendered
  offline; nothing is stored or cached.
- **Small runtime image** – a static Go binary on Alpine with `lynx`, running as
  an unprivileged user.
- **Multi-arch** – published for `linux/amd64` and `linux/arm64`.

## Quick start

```bash
docker run --rm -p 8080:8080 ghcr.io/clove3am/docker-html2txt:latest
```

Then open <http://localhost:8080> in a browser, or use the API directly:

```bash
curl 'http://localhost:8080/?url=https://example.com'
```

### Docker Compose

```yaml
services:
  html2txt:
    image: ghcr.io/clove3am/docker-html2txt:latest
    ports:
      - "8080:8080"
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
```

## API

| Request | Response |
| --- | --- |
| `GET /` | HTML form for interactive use |
| `GET /?url=<url>` | `text/plain; charset=utf-8` with the rendered page |
| `HEAD /?url=<url>` | Same headers as above, without the body |
| `GET /healthz` | `ok` (used by the container health check) |

Errors are returned as plain text:

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | Missing or invalid URL, unsupported scheme, or URL longer than 2048 characters |
| `403 Forbidden` | The host resolves to a private, loopback or otherwise reserved address |
| `405 Method Not Allowed` | Anything other than `GET` or `HEAD` |
| `502 Bad Gateway` | The page could not be resolved, downloaded or converted |
| `503 Service Unavailable` | Too many conversions in flight; retry later |

## Security

The service fetches URLs supplied by users, so it treats every URL as hostile:

- **Scheme allow-list** – only `http` and `https`; `file://`, `gopher://`,
  `javascript:` and friends are rejected. URLs with embedded credentials are
  rejected too.
- **Public addresses only** – loopback, private (RFC 1918 / ULA), link-local,
  multicast, unspecified, carrier-grade NAT and reserved ranges are blocked,
  including IPv4-mapped IPv6 forms. This covers cloud metadata services such as
  `169.254.169.254`.
- **Connect-time validation** – the HTTP dialer checks the resolved IP of every
  connection attempt and refuses redirects to other schemes. A DNS answer that
  changes to an internal address after validation (DNS rebinding) is blocked.
- **No upstream proxy** – `HTTP_PROXY`-style proxy settings are ignored, because
  a proxy would make the request on our behalf and bypass the address checks.
- **No network access for lynx** – the page is downloaded by Go and passed to
  `lynx` on stdin, so lynx never makes its own requests.
- **Bounded work** – 5 MiB maximum download, 25 second request timeout,
  15 second render timeout, 5 redirects maximum, 16 concurrent conversions and
  an HTTP server with read/write/idle timeouts.
- **Minimal privileges** – the container runs as a non-root user and needs only
  a writable temporary directory for lynx, which can be a tmpfs.

Even so, run it behind a reverse proxy with rate limiting if you expose it to
the internet, and apply an egress firewall policy to the container's network if
you want defence in depth.

## Limitations

- JavaScript-heavy sites will only show their server-rendered content.
- Pages that require login or cookies cannot be fetched.
- Redirects are limited to 5 hops.
- Binary content (PDF, images, archives) is rejected rather than converted.
- Text layout comes from Lynx, so wide pages may look sparse.

## Troubleshooting

**`Failed to convert the requested page.` with `lynx: exit status 1` in the log**

lynx spools documents read from stdin to a temporary file. The service uses
`/dev/shm` when it is writable (Docker provides it as a tmpfs even with
`read_only: true`) and falls back to `/tmp`. If both are read-only, give the
container a writable `/tmp`:

```yaml
services:
  html2txt:
    read_only: true
    tmpfs:
      - /tmp
```

The error message includes lynx's own output, for example
`stdout: "/tmp/lynxXXXX: Read-only file system"`, and the service logs
`no writable temporary directory found` at startup when this is the case.

**`Could not resolve the host in the requested URL.`**

The container cannot reach a DNS server, or the hostname does not exist. Check
the container's network settings.

## Development

Requirements: Go 1.24+ and `lynx` (needed for the conversion tests, which are
skipped when it is missing).

```bash
gofmt -l .          # formatting
go vet ./...        # static checks
go test ./...       # tests
go run .            # start on http://localhost:8080
```

Build the container image locally:

```bash
docker build -t html2txt .
docker run --rm -p 8080:8080 html2txt
```

### Releases

Pushes to `main` publish `main`, `sha-<commit>` and `latest` tags to GHCR.
Pushing a semver tag (`v1.2.3`) additionally publishes `1.2.3` and `1.2`:

```bash
git tag v1.2.3
git push origin v1.2.3
```

Docker, Go and GitHub Actions dependencies are updated by Dependabot.

## License

[MIT](LICENSE)
