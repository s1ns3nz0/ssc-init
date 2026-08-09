package webhook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

var ErrDelivery = errors.New("webhook delivery failed")

const maxBody = 1 << 20

type Deliverer struct{ Client *http.Client }

func (d Deliverer) Deliver(ctx context.Context, destination string, body []byte) error {
	parsed, err := url.Parse(destination)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || len(body) == 0 || len(body) > maxBody {
		return ErrDelivery
	}
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return ErrDelivery
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return ErrDelivery
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrDelivery
	}
	return nil
}
