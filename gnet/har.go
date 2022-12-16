package gnet

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/google/martian/v3/har"
	"github.com/mel2oo/go-pcap/memview"
	"github.com/pkg/errors"
)

func (r *HTTPRequest) FromHAR(h *har.Request) error {
	r.Method = h.Method

	// HTTP version
	{
		if strings.ToUpper(h.HTTPVersion) == "HTTP/2" {
			// Firefox uses "HTTP/2" instead of "HTTP/2.0".
			r.ProtoMajor = 2
			r.ProtoMinor = 0
		} else {
			major, minor, ok := http.ParseHTTPVersion(strings.ToUpper(h.HTTPVersion))
			if ok {
				r.ProtoMajor = major
				r.ProtoMinor = minor
			}
			// Ignore HTTP version parsing error. We've seen HAR files in the wild
			// with empty HTTP version strings.
		}
	}

	// URL
	{
		u, err := url.Parse(h.URL)
		if err != nil {
			return errors.Wrap(err, "failed to parse URL")
		}

		vals := make(url.Values)
		for _, q := range h.QueryString {
			vals.Add(q.Name, q.Value)
		}
		u.RawQuery = vals.Encode()

		r.URL = u
		r.Host = u.Host
	}

	// Header and host.
	headers, host := convertHARHeaders(h.Headers)
	r.Header = headers
	if r.Host == "" {
		// Some HAR generators record the full URL with host while some only record
		// the path in the URL field, so we fallback to use host header.
		r.Host = host
	}

	// Cookies
	r.Cookies = convertHARCookies(h.Cookies)

	// Body
	if pd := h.PostData; pd != nil {
		r.Header.Set("Content-Type", pd.MimeType)

		// URL encoded body
		if len(pd.Params) > 0 {
			vals := make(url.Values)
			for _, p := range pd.Params {
				vals.Add(p.Name, p.Value)
			}
			r.Body = memview.New([]byte(vals.Encode()))
		} else {
			r.Body = memview.New([]byte(pd.Text))
		}

		// HAR records HTTP decoded body.
		r.BodyDecompressed = true
	}

	return nil
}

func (r *HTTPResponse) FromHAR(h *har.Response) error {
	if h.Status < 200 || h.Status > 599 {
		return errors.Errorf("status code %v out of range", h.Status)
	}
	r.StatusCode = h.Status

	// HTTP version
	{
		if strings.ToUpper(h.HTTPVersion) == "HTTP/2" {
			// Firefox uses "HTTP/2" instead of "HTTP/2.0".
			r.ProtoMajor = 2
			r.ProtoMinor = 0
		} else {
			major, minor, ok := http.ParseHTTPVersion(strings.ToUpper(h.HTTPVersion))
			if ok {
				r.ProtoMajor = major
				r.ProtoMinor = minor
			}
			// Ignore HTTP version parsing error. We've seen HAR files in the wild
			// with empty HTTP version strings.
		}
	}

	headers, _ := convertHARHeaders(h.Headers)
	r.Header = headers

	// TODO(kku): Our OpeanAPI converter does not expect cookies in response yet.
	// r.Cookies = convertHARCookies(h.Cookies)

	if c := h.Content; c != nil {
		r.Header.Set("Content-Type", c.MimeType)

		// HAR records HTTP decoded body.
		r.BodyDecompressed = true

		switch c.Encoding {
		case "base64":
			// The martian har library performs the decoding for us.
			// See https://github.com/google/martian/pull/314
			fallthrough
		case "":
			r.Body = memview.New(c.Text)
		default:
			return errors.Errorf("unsupported encoding %s", c.Encoding)
		}
	}

	return nil
}

func convertHARHeaders(headers []har.Header) (http.Header, string) {
	results := make(http.Header, len(headers))
	var host string
	for _, header := range headers {
		if strings.ToLower(header.Name) == "host" {
			host = header.Value
		} else {
			results.Add(header.Name, header.Value)
		}
	}
	return results, host
}

func convertHARCookies(cs []har.Cookie) []*http.Cookie {
	results := make([]*http.Cookie, 0, len(cs))
	for _, c := range cs {
		results = append(results, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Expires:  c.Expires,
			HttpOnly: c.HTTPOnly,
			Secure:   c.Secure,
		})
	}
	return results
}
