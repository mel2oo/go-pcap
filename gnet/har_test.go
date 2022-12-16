package gnet

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/martian/v3/har"
	"github.com/mel2oo/go-pcap/memview"
	"github.com/stretchr/testify/assert"
)

var (
	harEntry = `{
	"_id":"wit_2YIGMI6wpbDaxPuiABCDEF",
	"request":{
		"method":"GET",
		"url":"/v1/projects/foo",
		"httpVersion":"HTTP/1.1",
		"cookies":[],
		"headers":[
			{"name":"Authorization","value":"bearer 123"},
			{"name":"Host","value":"localhost:3030"},
			{"name":"Content-Type","value":"application/x-www-form-urlencoded"}
		],
		"queryString":[
			{"name":"hello","value":"world"}
		],
		"postData":{
			"mimeType":"application/x-www-form-urlencoded",
			"params":[
				{"name":"koala","value":"1"},
				{"name":"bear","value":"0"}
			]
		},
		"headersSize":-1,
		"bodySize":0
	},
	"response":{
		"status":200,
		"statusText":"OK",
		"httpVersion":"HTTP/1.1",
		"cookies":[],
		"headers":[
			{"name":"Content-Type","value":"application/json"},
			{"name":"Content-Length","value":"22"}
		],
		"content":{
			"size":22,
			"mimeType":"application/json",
			"text":"ewogICJoZWxsbyI6ICJ3b3JsZCIKfQ==",
			"encoding":"base64"
		},
		"redirectURL":"",
		"headersSize":-1,
		"bodySize":22
	}
}`
)

func TestHTTPRequestFromHAR(t *testing.T) {
	var entry har.Entry
	assert.NoError(t, json.Unmarshal([]byte(harEntry), &entry))

	var r HTTPRequest
	assert.NoError(t, r.FromHAR(entry.Request))

	expected := HTTPRequest{
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL: &url.URL{
			Path:     "/v1/projects/foo",
			RawQuery: "hello=world",
		},
		Host: "localhost:3030",
		Header: map[string][]string{
			"Authorization": {"bearer 123"},
			"Content-Type":  {"application/x-www-form-urlencoded"},
		},
		Body:             memview.New([]byte(`bear=0&koala=1`)),
		BodyDecompressed: true,
		Cookies:          []*http.Cookie{},
	}
	assert.Equal(t, expected, r)
}

func TestHTTPResponseFromHAR(t *testing.T) {
	var entry har.Entry
	assert.NoError(t, json.Unmarshal([]byte(harEntry), &entry))

	var r HTTPResponse
	assert.NoError(t, r.FromHAR(entry.Response))

	expected := HTTPResponse{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: map[string][]string{
			"Content-Length": {"22"},
			"Content-Type":   {"application/json"},
		},
		Body:             memview.New([]byte("{\n  \"hello\": \"world\"\n}")),
		BodyDecompressed: true,
	}
	assert.Equal(t, expected, r)
}
