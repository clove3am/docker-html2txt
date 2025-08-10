package main

import (
	"testing"
)

func TestIsSSRFProne(t *testing.T) {
	// Define all the test cases in a table
	testCases := []struct {
		name          string // A descriptive name for the test case
		inputURL      string // The URL to test
		expectBlocked bool   // The expected boolean result from the function
		expectError   bool   // Whether we expect the function to return an error
	}{
		// --- Cases that should be ALLOWED ---
		{
			name:          "Public Domain",
			inputURL:      "https://example.com",
			expectBlocked: false,
			expectError:   false,
		},
		{
			name:          "Public Domain with Path",
			inputURL:      "http://google.com/search",
			expectBlocked: false,
			expectError:   false,
		},

		// --- Cases that should be BLOCKED (SSRF attempts) ---
		{
			name:          "Loopback Hostname",
			inputURL:      "http://localhost/admin",
			expectBlocked: true,
			expectError:   false,
		},
		{
			name:          "Loopback IPv4 Address",
			inputURL:      "https://127.0.0.1:8080",
			expectBlocked: true,
			expectError:   false,
		},
		{
			name:          "Loopback IPv6 Address",
			inputURL:      "http://[::1]/",
			expectBlocked: true,
			expectError:   false,
		},
		{
			name:          "Private Network IP (10.x.x.x)",
			inputURL:      "http://10.0.0.5/api",
			expectBlocked: true,
			expectError:   false,
		},
		{
			name:          "Private Network IP (192.168.x.x)",
			inputURL:      "https://192.168.1.100",
			expectBlocked: true,
			expectError:   false,
		},
		{
			name:          "Link-Local IP",
			inputURL:      "http://169.254.169.254/latest/meta-data",
			expectBlocked: true,
			expectError:   false,
		},

		// --- Cases that should produce an ERROR ---
		{
			name:          "Malformed URL",
			inputURL:      "htp:/totally-a-website",
			expectBlocked: true, // Function returns true on error
			expectError:   true,
		},
		{
			name:          "Hostname does not exist",
			inputURL:      "https://thishostnamedoesnotexist.local",
			expectBlocked: true, // Function returns true on error
			expectError:   true,
		},
	}

	// Loop through all the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Run the function we want to test
			blocked, err := isSSRFProne(tc.inputURL)

			// Check if the 'blocked' result matches our expectation
			if blocked != tc.expectBlocked {
				t.Errorf("Expected blocked=%v, but got blocked=%v for URL %s", tc.expectBlocked, blocked, tc.inputURL)
			}

			// Check if we got an error when we expected one, and vice-versa
			if (err != nil) != tc.expectError {
				t.Errorf("Expected error=%v, but got error=%v for URL %s", tc.expectError, err, tc.inputURL)
			}
		})
	}
}
