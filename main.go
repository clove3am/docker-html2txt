package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"time"
)

// The HTML for the form page. We embed it here for simplicity.
const formHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
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

// isSSRFProne checks if the hostname in a URL resolves to a private, loopback,
// or otherwise non-public IP address to prevent Server-Side Request Forgery (SSRF).
func isSSRFProne(targetURL string) (bool, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return true, fmt.Errorf("could not parse URL: %w", err)
	}

	hostname := parsedURL.Hostname()

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return true, fmt.Errorf("could not resolve hostname: %w", err)
	}

	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			log.Printf("Blocked SSRF attempt to a non-public IP: %s (%s)", hostname, ip.String())
			return true, nil
		}
	}

	return false, nil
}

func textHandler(w http.ResponseWriter, r *http.Request) {
	urlToFetch := r.URL.Query().Get("url")

	// If no URL is provided in the query, show the HTML form.
	if urlToFetch == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, formHTML)
		return
	}

	// --- Security Checks ---
	if _, err := url.ParseRequestURI(urlToFetch); err != nil {
		http.Error(w, "Invalid URL format.", http.StatusBadRequest)
		return
	}

	isBlocked, err := isSSRFProne(urlToFetch)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error during security check: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	if isBlocked {
		http.Error(w, "Request blocked: requests to private, loopback, or reserved IP addresses are not allowed.", http.StatusForbidden)
		return
	}

	// --- Execute Secure Lynx Command ---
	cmd := exec.Command("lynx",
		"-dump",
		"-force_html",
		"-display_charset=UTF-8",
		"-width=1024",
		"-dont_wrap_pre",
		"-cookie_file=/dev/null",
		"-cache=0",
		"-nolog",
		"-anonymous",
		urlToFetch,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := fmt.Sprintf("Error fetching URL with lynx: %v\nOutput:\n%s", err, string(output))
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}

func main() {
	http.HandleFunc("/", textHandler)

	fmt.Println("Secure Go html2txt server starting on port 8080...")
	server := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 3 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("could not listen on port 8080 %v", err)
	}
}
