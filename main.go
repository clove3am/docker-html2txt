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
	// Get the URL from the query string
	urlToFetch := r.URL.Query().Get("url")

	// --- Initial Validation ---
	if urlToFetch == "" {
		http.Error(w, "Please provide a 'url' query parameter.", http.StatusBadRequest)
		return
	}

	if _, err := url.ParseRequestURI(urlToFetch); err != nil {
		http.Error(w, "Invalid URL format.", http.StatusBadRequest)
		return
	}

	// --- SSRF Prevention ---
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
	// Using the hardened set of flags for stateless and secure execution.
	// We pass the URL as the final, separate argument to prevent command injection.
	cmd := exec.Command("lynx",
		"-dump",
		"-nonumbers",
		"-listonly",
		"-cookie_file=/dev/null", // Discard all cookies
		"-cache=0",               // Set in-memory cache size to 0
		"-nolog",                 // Do not create a log file
		"-nostatus",              // Do not show status messages
		"-anonymous",             // Use anonymous/generic headers
		urlToFetch,
	)

	// Execute the command and capture the output
	output, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := fmt.Sprintf("Error fetching URL with lynx: %v\nOutput:\n%s", err, string(output))
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	// Return the output as plain text
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
