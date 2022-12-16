package http

const (
	// Length of the shortest HTTP method that we support.
	// 3 == len(`GET`)
	minSupportedHTTPMethodLength = 3

	// Length of the longest HTTP method that we support.
	// 7 == len(`CONNECT`)
	maxSupportedHTTPMethodLength = 7

	// Maximum request URI length that our parser accepts. There is no standard,
	// but 2000 bytes seem to be the de facto standard, so we double it.
	// https://stackoverflow.com/questions/417142
	maxHTTPRequestURILength = 4000

	// Maximum length of the HTTP status code reason phrase in a response that our
	// parser accepts.
	maxHTTPReasonPhraseLength = 512

	// Minimum amount of HTTP response status line (RFC 2616 Section 6.1) that we
	// need to see before accepting some bytes as HTTP response.
	// 12 == len(`HTTP/1.1 200`)
	minHTTPResponseStatusLineLength = 12
)

var (
	// Sorted with more common ones near the front.
	// Remember to update maxSupportedHTTPMethodLength if necessary.
	supportedHTTPMethods = []string{
		"GET",
		"POST",
		"DELETE",
		"HEAD",
		"PUT",
		"PATCH",
		"CONNECT",
		"OPTIONS",
		"TRACE",
	}
)
