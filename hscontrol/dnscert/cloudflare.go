package dnscert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultCloudflareAPI is Cloudflare's v4 API base URL.
const DefaultCloudflareAPI = "https://api.cloudflare.com/client/v4"

// challengeComment marks the records this package creates, so CleanTXT
// only ever removes its own.
const challengeComment = "ACME challenge, removed after validation"

// Cloudflare publishes and removes the ACME TXT records through the
// Cloudflare API. The token is read from a file on every call and never
// appears in an error or a log line: it can edit the zone's DNS.
type Cloudflare struct {
	Zone      string
	TokenPath string
	BaseURL   string
	HTTP      *http.Client

	// zoneMu guards zoneID: node challenges look the zone up concurrently.
	zoneMu sync.Mutex
	zoneID string
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

var errCloudflare = errors.New("cloudflare api")

func (c *Cloudflare) base() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}

	return DefaultCloudflareAPI
}

func (c *Cloudflare) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}

	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Cloudflare) token() (string, error) {
	raw, err := os.ReadFile(c.TokenPath)
	if err != nil {
		return "", fmt.Errorf("reading cloudflare token file: %w", err)
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%w: token file %s is empty", errCloudflare, c.TokenPath)
	}

	return token, nil
}

func (c *Cloudflare) call(ctx context.Context, method, path string, body any, out any) error {
	token, err := c.token()
	if err != nil {
		return err
	}

	var reader *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding cloudflare request: %w", err)
		}

		reader = bytes.NewReader(buf)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, reader)
	if err != nil {
		return fmt.Errorf("building cloudflare request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s %s: %w", errCloudflare, method, path, err)
	}
	defer resp.Body.Close()

	var parsed cfResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil { //nolint:noinlineerr
		return fmt.Errorf("%w: %s %s: status %d, undecodable body", errCloudflare, method, path, resp.StatusCode)
	}

	if !parsed.Success {
		msgs := make([]string, 0, len(parsed.Errors))
		for _, e := range parsed.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}

		return fmt.Errorf("%w: %s %s: status %d: %s", errCloudflare, method, path, resp.StatusCode, strings.Join(msgs, "; "))
	}

	if out != nil {
		if err := json.Unmarshal(parsed.Result, out); err != nil { //nolint:noinlineerr
			return fmt.Errorf("%w: decoding result of %s %s: %w", errCloudflare, method, path, err)
		}
	}

	return nil
}

func (c *Cloudflare) zone(ctx context.Context) (string, error) {
	c.zoneMu.Lock()
	defer c.zoneMu.Unlock()

	if c.zoneID != "" {
		return c.zoneID, nil
	}

	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	if err := c.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(c.Zone), nil, &zones); err != nil { //nolint:noinlineerr
		return "", err
	}

	for _, z := range zones {
		if strings.EqualFold(z.Name, c.Zone) {
			c.zoneID = z.ID

			return z.ID, nil
		}
	}

	return "", fmt.Errorf("%w: zone %s not visible to this token", errCloudflare, c.Zone)
}

// SetTXT creates a TXT record and returns its id for DeleteRecord.
func (c *Cloudflare) SetTXT(ctx context.Context, name, value string) (string, error) {
	zone, err := c.zone(ctx)
	if err != nil {
		return "", err
	}

	var rec struct {
		ID string `json:"id"`
	}

	err = c.call(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", map[string]any{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     60,
		"comment": challengeComment,
	}, &rec)
	if err != nil {
		return "", err
	}

	return rec.ID, nil
}

// CleanTXT removes the TXT records for name that carry this package's mark.
func (c *Cloudflare) CleanTXT(ctx context.Context, name string) error {
	zone, err := c.zone(ctx)
	if err != nil {
		return err
	}

	var recs []struct {
		ID      string `json:"id"`
		Comment string `json:"comment"`
	}

	if err := c.call(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?type=TXT&name="+url.QueryEscape(name), nil, &recs); err != nil { //nolint:noinlineerr
		return err
	}

	for _, r := range recs {
		if r.Comment != challengeComment {
			continue
		}

		if err := c.DeleteRecord(ctx, r.ID); err != nil { //nolint:noinlineerr
			return err
		}
	}

	return nil
}

// DeleteRecord removes a record created by SetTXT.
func (c *Cloudflare) DeleteRecord(ctx context.Context, id string) error {
	zone, err := c.zone(ctx)
	if err != nil {
		return err
	}

	return c.call(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+url.PathEscape(id), nil, nil)
}
