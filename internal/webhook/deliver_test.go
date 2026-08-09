package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeliverSendsExactBodyOnlyToExplicitHTTPSDestination(t *testing.T) {
	want := []byte(`{"schemaVersion":"ssc-init.findings.v1"}`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		got, _ := io.ReadAll(request.Body)
		if string(got) != string(want) || request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("body=%q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if err := (Deliverer{Client: server.Client()}).Deliver(context.Background(), server.URL, want); err != nil {
		t.Fatal(err)
	}
}

func TestDeliverRejectsUnsafeDestinationBeforeOpeningSocket(t *testing.T) {
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { t.Fatal("network opened"); return nil, nil })}
	for _, destination := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com/#fragment", "not-a-url"} {
		if err := (Deliverer{Client: client}).Deliver(context.Background(), destination, []byte("{}")); err != ErrDelivery {
			t.Fatalf("destination=%q err=%v", destination, err)
		}
	}
	if err := (Deliverer{Client: client}).Deliver(context.Background(), "https://example.com", []byte(strings.Repeat("x", maxBody+1))); err != ErrDelivery {
		t.Fatalf("oversize err=%v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
