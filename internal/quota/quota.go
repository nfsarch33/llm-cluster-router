// Package quota detects vendor quota-exhaustion responses and posts
// Slack notifications when the failover chain triggers a fallback.
//
// The detector inspects response bodies against a configurable regex
// supplied by the active node's QuotaDetectRegex configuration. When
// matched, the metric QuotaFallbackTotal is incremented and a Slack
// webhook is posted (best-effort; failures do not affect user response).
package quota

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"
)

// Detector matches a response body against a quota-exhaustion regex and
// posts a Slack notification when matched.
type Detector struct {
	pattern    *regexp.Regexp
	webhookURL string
	channel    string
	httpClient *http.Client
	logger     *slog.Logger
}

// New constructs a Detector. A nil or empty webhookURL disables Slack
// notifications (but does not disable the metric increment). A nil or
// empty pattern returns nil so callers can skip the check cheaply.
func New(pattern, webhookURL, channel string, logger *slog.Logger) *Detector {
	if pattern == "" {
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		if logger != nil {
			logger.Warn("quota: invalid pattern; disabling detector", "err", err)
		}
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Detector{
		pattern:    re,
		webhookURL: webhookURL,
		channel:    channel,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		logger:     logger,
	}
}

// Matches returns true iff the body matches the detector pattern.
func (d *Detector) Matches(body []byte) bool {
	if d == nil || d.pattern == nil {
		return false
	}
	return d.pattern.Match(body)
}

// Notify increments the metric and, if a webhook URL is configured, posts
// a Slack message. Body is the captured response body. Failures are
// logged but never returned; the upstream response is unaffected.
func (d *Detector) Notify(model, node, vendor string, body []byte) {
	if d == nil {
		return
	}
	if d.webhookURL != "" {
		go d.postSlack(model, node, vendor, body)
	}
}

func (d *Detector) postSlack(model, node, vendor string, body []byte) {
	text := d.buildSlackText(model, node, vendor, body)
	payload := map[string]string{"text": text}
	if d.channel != "" {
		payload["channel"] = d.channel
	}
	json, err := encodeJSON(payload)
	if err != nil {
		d.logger.Warn("quota: failed to encode Slack payload", "err", err)
		return
	}
	resp, err := d.httpClient.Post(d.webhookURL, "application/json", bytes.NewReader(json))
	if err != nil {
		d.logger.Warn("quota: slack webhook post failed", "err", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		d.logger.Warn("quota: slack webhook non-2xx", "status", resp.StatusCode)
	}
}

func (d *Detector) buildSlackText(model, node, vendor string, body []byte) string {
	preview := body
	if len(preview) > 200 {
		preview = preview[:200]
	}
	return fmt.Sprintf(":warning: *Quota fallback* | model=`%s` node=`%s` vendor=`%s`\n```%s```",
		model, node, vendor, string(preview))
}
