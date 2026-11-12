package main

import (
	"context"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// stubLookup replaces the DNS resolver for the duration of a test.
func stubLookup(t *testing.T, fn func(context.Context, string) ([]net.IPAddr, error)) {
	t.Helper()
	original := lookupIPAddr
	lookupIPAddr = fn
	t.Cleanup(func() { lookupIPAddr = original })
}

// staticLookup returns a resolver stub that always resolves to ips.
func staticLookup(ips ...string) func(context.Context, string) ([]net.IPAddr, error) {
	return func(context.Context, string) ([]net.IPAddr, error) {
		addrs := make([]net.IPAddr, 0, len(ips))
		for _, ip := range ips {
			addrs = append(addrs, net.IPAddr{IP: net.ParseIP(ip)})
		}
		return addrs, nil
	}
}

func TestIsBlockedIP(t *testing.T) {
	testCases := []struct {
		ip      string
		blocked bool
	}{
		// Public addresses.
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"2606:4700:4700::1111", false},

		// Loopback.
		{"127.0.0.1", true},
		{"127.10.20.30", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true},

		// Private networks.
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"fd00::1", true},
		{"::ffff:192.168.1.1", true},

		// Link-local, including the cloud metadata endpoint.
		{"169.254.169.254", true},
		{"fe80::1", true},

		// Reserved and otherwise unroutable ranges.
		{"0.0.0.0", true},
		{"100.64.0.1", true}, // carrier-grade NAT
		{"192.0.2.5", true},  // documentation
		{"198.18.0.1", true}, // benchmarking
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"2001:db8::1", true},
		{"2002:7f00:1::", true}, // 6to4 wrapping 127.0.0.1

		// Multicast.
		{"224.0.0.1", true},
		{"ff02::1", true},
	}

	for _, tc := range testCases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("could not parse %q", tc.ip)
			}
			if got := isBlockedIP(ip); got != tc.blocked {
				t.Errorf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}

func TestCheckHostAllowed(t *testing.T) {
	testCases := []struct {
		name    string
		host    string
		lookup  func(context.Context, string) ([]net.IPAddr, error)
		blocked bool
		wantErr bool
	}{
		{
			name:   "public hostname",
			host:   "example.com",
			lookup: staticLookup("93.184.216.34"),
		},
		{
			name: "public IP literal",
			host: "1.1.1.1",
		},
		{
			name:    "localhost hostname",
			host:    "localhost",
			lookup:  staticLookup("127.0.0.1"),
			blocked: true,
		},
		{
			name:    "loopback IPv4 literal",
			host:    "127.0.0.1",
			blocked: true,
		},
		{
			name:    "loopback IPv6 literal",
			host:    "::1",
			blocked: true,
		},
		{
			name:    "private IPv4 literal",
			host:    "10.0.0.5",
			blocked: true,
		},
		{
			name:    "cloud metadata literal",
			host:    "169.254.169.254",
			blocked: true,
		},
		{
			name:    "hostname resolving to one private address",
			host:    "internal.example.com",
			lookup:  staticLookup("93.184.216.34", "10.0.0.5"),
			blocked: true,
		},
		{
			name:    "unresolvable hostname",
			host:    "does-not-exist.example",
			lookup:  func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("no such host") },
			wantErr: true,
		},
		{
			name:    "no addresses",
			host:    "empty.example",
			lookup:  staticLookup(),
			wantErr: true,
		},
		{
			name:    "empty host",
			host:    "",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.lookup != nil {
				stubLookup(t, tc.lookup)
			}

			err := checkHostAllowed(context.Background(), tc.host)

			if tc.blocked {
				if !errors.Is(err, errBlockedAddress) {
					t.Fatalf("expected errBlockedAddress, got %v", err)
				}
				return
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if errors.Is(err, errBlockedAddress) {
					t.Fatalf("did not expect errBlockedAddress, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	testCases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "https", raw: "https://example.com"},
		{name: "http with path and query", raw: "http://example.com/foo?bar=1"},
		{name: "uppercase scheme", raw: "HTTPS://example.com"},
		{name: "IPv6 literal", raw: "http://[::1]/"},
		{name: "missing scheme", raw: "example.com", wantErr: true},
		{name: "file scheme", raw: "file:///etc/passwd", wantErr: true},
		{name: "ftp scheme", raw: "ftp://example.com/file", wantErr: true},
		{name: "javascript scheme", raw: "javascript:alert(1)", wantErr: true},
		{name: "gopher scheme", raw: "gopher://example.com", wantErr: true},
		{name: "no host", raw: "http://", wantErr: true},
		{name: "embedded credentials", raw: "http://user:pass@example.com/", wantErr: true},
		{name: "malformed", raw: "htp:/totally-a-website", wantErr: true},
		{name: "control characters", raw: "http://example.com/\x00", wantErr: true},
		{name: "too long", raw: "https://example.com/" + strings.Repeat("a", maxURLLength), wantErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTarget(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseTarget(%q) error = %v, wantErr %v", tc.raw, err, tc.wantErr)
			}
		})
	}
}

func TestCheckDialAddress(t *testing.T) {
	testCases := []struct {
		address string
		blocked bool
	}{
		{address: "93.184.216.34:80"},
		{address: "93.184.216.34:443"},
		{address: "[2606:4700:4700::1111]:443"},
		{address: "127.0.0.1:8080", blocked: true},
		{address: "169.254.169.254:80", blocked: true},
		{address: "[::1]:80", blocked: true},
		{address: "10.0.0.1:80", blocked: true},
		{address: "not-an-address", blocked: true},
	}

	for _, tc := range testCases {
		t.Run(tc.address, func(t *testing.T) {
			err := checkDialAddress(tc.address)
			if tc.blocked {
				if !errors.Is(err, errBlockedAddress) {
					t.Fatalf("expected errBlockedAddress, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestIsTextual(t *testing.T) {
	testCases := []struct {
		contentType string
		want        bool
	}{
		{"", true},
		{"text/html", true},
		{"text/html; charset=utf-8", true},
		{"text/plain", true},
		{"application/xhtml+xml", true},
		{"application/xml", true},
		{"application/pdf", false},
		{"image/png", false},
		{"application/octet-stream", false},
	}

	for _, tc := range testCases {
		t.Run(tc.contentType, func(t *testing.T) {
			mediaType := tc.contentType
			if mediaType != "" {
				parsed, _, err := mime.ParseMediaType(mediaType)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.contentType, err)
				}
				mediaType = parsed
			}
			if got := isTextual(mediaType); got != tc.want {
				t.Errorf("isTextual(%q) = %v, want %v", tc.contentType, got, tc.want)
			}
		})
	}
}

func TestHTMLToText(t *testing.T) {
	if _, err := exec.LookPath("lynx"); err != nil {
		t.Skip("lynx is not installed")
	}

	document := []byte(`<html><head><title>Test</title></head>
		<body><h1>Heading</h1><p>Hello &amp; welcome to the <a href="/x">site</a>.</p></body></html>`)

	text, err := htmlToText(context.Background(), document, "")
	if err != nil {
		t.Fatalf("htmlToText returned an error: %v", err)
	}

	got := string(text)
	for _, want := range []string{"Heading", "Hello & welcome", "site"} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not contain %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"<h1>", "<p>", "<html>"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("output still contains markup %q:\n%s", unwanted, got)
		}
	}
}

func TestHTMLToTextCharset(t *testing.T) {
	if _, err := exec.LookPath("lynx"); err != nil {
		t.Skip("lynx is not installed")
	}

	// "Café" encoded as ISO-8859-1.
	document := []byte("<html><body><p>Caf\xe9</p></body></html>")

	text, err := htmlToText(context.Background(), document, "iso-8859-1")
	if err != nil {
		t.Fatalf("htmlToText returned an error: %v", err)
	}
	if !strings.Contains(string(text), "Café") {
		t.Errorf("expected the charset to be converted to UTF-8, got:\n%s", text)
	}
}

func TestHandlerFormPage(t *testing.T) {
	srv := newServer()
	rec := httptest.NewRecorder()

	srv.handleConvert(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), `name="url"`) {
		t.Error("form page does not contain the url input")
	}
}

func TestHandlerRejectsBadRequests(t *testing.T) {
	srv := newServer()

	testCases := []struct {
		name       string
		method     string
		target     string
		wantStatus int
	}{
		{
			name:       "unsupported method",
			method:     http.MethodPost,
			target:     "/",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "file scheme",
			method:     http.MethodGet,
			target:     "/?url=file%3A%2F%2F%2Fetc%2Fpasswd",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing scheme",
			method:     http.MethodGet,
			target:     "/?url=example.com",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "loopback literal",
			method:     http.MethodGet,
			target:     "/?url=http%3A%2F%2F127.0.0.1%3A8080%2F",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "metadata service",
			method:     http.MethodGet,
			target:     "/?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "private network literal",
			method:     http.MethodGet,
			target:     "/?url=http%3A%2F%2F10.0.0.5%2F",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.handleConvert(rec, httptest.NewRequest(tc.method, tc.target, nil))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestHandlerBlocksPrivateDNS(t *testing.T) {
	// A public looking hostname that resolves to a private address.
	stubLookup(t, staticLookup("127.0.0.1"))

	srv := newServer()
	rec := httptest.NewRecorder()
	srv.handleConvert(rec, httptest.NewRequest(http.MethodGet, "/?url=http%3A%2F%2Frebind.example%2F", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandlerUnresolvableHost(t *testing.T) {
	stubLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("no such host")
	})

	srv := newServer()
	rec := httptest.NewRecorder()
	srv.handleConvert(rec, httptest.NewRequest(http.MethodGet, "/?url=http%3A%2F%2Fmissing.example%2F", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestHandleHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
}
