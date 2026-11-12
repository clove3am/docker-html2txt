// Command html2txt is a small web service that renders the contents of a web
// page as plain text. The page is downloaded by this server and rendered by
// the Lynx text browser, which is installed in the runtime image.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// listenAddr is the address the HTTP server listens on.
	listenAddr = ":8080"

	// maxURLLength is the maximum accepted length of the "url" query parameter.
	maxURLLength = 2048

	// maxResponseSize caps how much of the remote page is downloaded.
	maxResponseSize = 5 << 20 // 5 MiB

	// maxRedirects caps how many redirects are followed per request.
	maxRedirects = 5

	// requestTimeout bounds the whole request, including download and rendering.
	requestTimeout = 25 * time.Second

	// lynxTimeout bounds the lynx rendering step only.
	lynxTimeout = 15 * time.Second

	// maxConcurrent limits how many pages are converted at the same time.
	maxConcurrent = 16

	// userAgent is sent when fetching the page.
	userAgent = "html2txt/1.0 (+https://github.com/clove3am/docker-html2txt)"
)

// errBlockedAddress is returned when a target resolves to a non-public address.
var errBlockedAddress = errors.New("blocked address")

// charsetPattern restricts charset names passed on to lynx to a safe subset.
var charsetPattern = regexp.MustCompile(`^[A-Za-z0-9._:+-]{1,40}$`)

// formHTML is the landing page shown when no URL was supplied.
const formHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
    <title>HTML to Text Converter</title>
    <style>
        body { font-family: sans-serif; background-color: #f4f4f9; color: #333; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #5a5a5a; }
        input[type="url"] { width: 300px; padding: 0.5rem; margin-top: 1rem; border: 1px solid #ccc; border-radius: 4px; }
        input[type="submit"] { padding: 0.6rem 1.2rem; margin-left: 0.5rem; border: none; background-color: #007bff; color: white; border-radius: 4px; cursor: pointer; }
        input[type="submit"]:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>HTML to Text Converter</h1>
        <p>Enter a URL to get its text-only version.</p>
        <form action="/" method="GET">
            <input type="url" id="url" name="url" placeholder="https://example.com" required>
            <input type="submit" value="Convert">
        </form>
    </div>
</body>
</html>
`

// Reserved address ranges that net.IP predicates do not cover but that must
// never be reachable from user supplied URLs.
var (
	reservedIPv4 = mustParseCIDRs(
		"0.0.0.0/8",     // "this" network
		"100.64.0.0/10", // carrier-grade NAT
		"192.0.0.0/24",  // IETF protocol assignments
		"192.0.2.0/24",  // documentation (TEST-NET-1)
		"198.18.0.0/15", // benchmarking
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4", // reserved, includes the broadcast address
	)
	reservedIPv6 = mustParseCIDRs(
		"100::/64",      // discard-only
		"2001:db8::/32", // documentation
		"2002::/16",     // 6to4, can embed private IPv4 addresses
	)
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR %q: %v", cidr, err))
		}
		nets = append(nets, ipNet)
	}
	return nets
}

// lookupIPAddr resolves a hostname. It is a variable so tests can stub it.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

// isBlockedIP reports whether ip is loopback, private, link-local, multicast,
// unspecified or otherwise reserved.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}

	if v4 := ip.To4(); v4 != nil {
		for _, n := range reservedIPv4 {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range reservedIPv6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// checkHostAllowed verifies that hostname only resolves to public addresses.
// It is a cheap early rejection; the authoritative check happens for every
// connection attempt in checkDialAddress.
func checkHostAllowed(ctx context.Context, hostname string) error {
	if hostname == "" {
		return errors.New("URL has no host")
	}

	if ip := net.ParseIP(hostname); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("%w: %s is not a public address", errBlockedAddress, ip)
		}
		return nil
	}

	// A literal hostname in brackets is IPv6; strip them before resolving.
	addrs, err := lookupIPAddr(ctx, strings.Trim(hostname, "[]"))
	if err != nil {
		return fmt.Errorf("could not resolve %q: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("could not resolve %q: no addresses", hostname)
	}
	for _, addr := range addrs {
		if isBlockedIP(addr.IP) {
			return fmt.Errorf("%w: %s resolves to non-public address %s", errBlockedAddress, hostname, addr.IP)
		}
	}
	return nil
}

// checkDialAddress validates the address of a single connection attempt. The
// dialer calls it after DNS resolution, which makes the check immune to DNS
// rebinding (a hostname that resolves to a public IP during validation and to
// a private one when the request is actually made).
func checkDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unexpected dial address %q: %v", errBlockedAddress, address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: dial address %q does not contain an IP address", errBlockedAddress, address)
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("%w: %s", errBlockedAddress, ip)
	}
	return nil
}

// parseTarget validates the user supplied URL.
func parseTarget(raw string) (*url.URL, error) {
	if len(raw) > maxURLLength {
		return nil, fmt.Errorf("URL is longer than %d characters", maxURLLength)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("only http and https URLs are supported")
	}
	if u.Hostname() == "" {
		return nil, errors.New("URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("URLs with embedded credentials are not supported")
	}
	return u, nil
}

// newSafeClient returns an HTTP client that refuses to connect to non-public
// addresses and does not use proxies (a proxy would make the connection on our
// behalf and bypass the address checks).
func newSafeClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddress(address)
		},
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxConcurrent,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to %q scheme", req.URL.Scheme)
			}
			return nil
		},
	}
}

// isTextual reports whether a Content-Type can meaningfully be rendered by lynx.
func isTextual(mediaType string) bool {
	if mediaType == "" {
		return true // no Content-Type: let lynx figure it out
	}
	return strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/xhtml+xml" ||
		mediaType == "application/xml"
}

// server holds the shared HTTP client and the concurrency limiter.
type server struct {
	client *http.Client
	sem    chan struct{}
}

func newServer() *server {
	return &server{
		client: newSafeClient(),
		sem:    make(chan struct{}, maxConcurrent),
	}
}

// fetch downloads target and returns its body and declared charset.
func (s *server) fetch(ctx context.Context, target *url.URL) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, "", fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	mediaType, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if !isTextual(mediaType) {
		return nil, "", fmt.Errorf("unsupported content type %q", mediaType)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, "", fmt.Errorf("response exceeds %d bytes", maxResponseSize)
	}

	charset := params["charset"]
	if !charsetPattern.MatchString(charset) {
		charset = ""
	}
	return body, charset, nil
}

// htmlToText renders HTML to plain text with lynx. The document is passed on
// stdin so lynx never performs network requests of its own.
func htmlToText(ctx context.Context, document []byte, charset string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, lynxTimeout)
	defer cancel()

	args := []string{
		"-dump",
		"-force_html", // treat stdin as HTML even without a Content-Type
		"-stdin",
		"-display_charset=UTF-8",
		"-width=1024",
		"-dont_wrap_pre",
		"-nolog",
		"-anonymous",
	}
	if charset != "" && !strings.EqualFold(charset, "utf-8") {
		args = append(args, "-assume_charset="+charset)
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "lynx", args...)
	cmd.Stdin = bytes.NewReader(document)
	cmd.Stderr = &stderr
	// Make sure a stuck child process cannot keep us waiting forever.
	cmd.WaitDelay = 2 * time.Second

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("lynx timed out: %w", err)
		}
		return nil, fmt.Errorf("lynx: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// serveForm writes the landing page.
func serveForm(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if _, err := io.WriteString(w, formHTML); err != nil {
		log.Printf("writing form page: %v", err)
	}
}

// handleConvert serves the landing page and the conversion endpoint.
func (s *server) handleConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Only GET and HEAD are supported.", http.StatusMethodNotAllowed)
		return
	}

	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		serveForm(w)
		return
	}

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "Server is busy, please try again shortly.", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	target, err := parseTarget(rawURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := checkHostAllowed(ctx, target.Hostname()); err != nil {
		if errors.Is(err, errBlockedAddress) {
			log.Printf("blocked request for %s: %v", target.Redacted(), err)
			http.Error(w, "Request blocked: the URL must resolve to a public address.", http.StatusForbidden)
			return
		}
		log.Printf("could not resolve host for %s: %v", target.Redacted(), err)
		http.Error(w, "Could not resolve the host in the requested URL.", http.StatusBadGateway)
		return
	}

	document, charset, err := s.fetch(ctx, target)
	if err != nil {
		log.Printf("fetch failed for %s: %v", target.Redacted(), err)
		http.Error(w, "Failed to fetch the requested URL.", http.StatusBadGateway)
		return
	}

	text, err := htmlToText(ctx, document, charset)
	if err != nil {
		log.Printf("conversion failed for %s: %v", target.Redacted(), err)
		http.Error(w, "Failed to convert the requested page.", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write(text); err != nil {
		log.Printf("writing response for %s: %v", target.Redacted(), err)
	}
}

// handleHealth is used by the container health check.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Only GET and HEAD are supported.", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := io.WriteString(w, "ok\n"); err != nil {
		log.Printf("writing health response: %v", err)
	}
}

func main() {
	srv := newServer()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleConvert)
	mux.HandleFunc("/healthz", handleHealth)

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      requestTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("html2txt listening on %s", listenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
