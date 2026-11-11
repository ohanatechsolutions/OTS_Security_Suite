package desktop

import (
	"net/http"
	"net/url"
	"testing"
)

func TestEphemeralPortSession(t *testing.T) {
	server, err := New()
	if err != nil {
		t.Fatal(err)
	}
	server.UseEphemeralPort()
	address, err := server.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer server.web.Close()
	parsed, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host == Addr || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "0" {
		t.Fatalf("bad ephemeral host: %s", parsed.Host)
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("session page returned %d", response.StatusCode)
	}
}
