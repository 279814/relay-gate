package security

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var (
	reUnicodeEscape = regexp.MustCompile(`(?:\\u[0-9a-fA-F]{4})+`)
	reBase64        = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)
)

type decodedValue struct {
	text           string
	hidden, failed bool
}

func decodedVariants(text string) []decodedValue {
	var out []decodedValue
	seen := map[string]bool{text: true}
	add := func(value string, hidden bool) {
		if !seen[value] {
			seen[value] = true
			out = append(out, decodedValue{text: value, hidden: hidden})
		}
	}
	if strings.Contains(text, "%") {
		value, err := url.PathUnescape(text)
		if err != nil {
			out = append(out, decodedValue{failed: true})
		} else {
			add(value, false)
		}
	}
	if strings.Contains(text, `\u`) {
		failed := strings.Contains(reUnicodeEscape.ReplaceAllString(text, ""), `\u`)
		value := reUnicodeEscape.ReplaceAllStringFunc(text, func(s string) string {
			var decoded string
			if err := json.Unmarshal([]byte(`"`+s+`"`), &decoded); err != nil {
				failed = true
				return s
			}
			return decoded
		})
		if failed {
			out = append(out, decodedValue{failed: true})
		} else {
			add(value, false)
		}
	}
	hidden := false
	value := strings.Map(func(c rune) rune {
		if hiddenRune(c) {
			hidden = true
			return -1
		}
		return c
	}, text)
	value = norm.NFKC.String(value)
	add(value, hidden)
	for _, token := range reBase64.FindAllString(text, 32) {
		var data []byte
		var err error
		switch {
		case strings.ContainsAny(token, "-_"):
			data, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
		default:
			data, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(token, "="))
		}
		if err != nil {
			if strings.Contains(token, "=") {
				out = append(out, decodedValue{failed: true})
			}
			continue
		}
		if !utf8.Valid(data) || !printable(data) {
			continue
		}
		add(string(data), false)
	}
	return out
}

func hiddenRune(c rune) bool {
	return c == 0x00ad || c == 0x034f || c == 0x061c || c == 0x180e || c >= 0x200b && c <= 0x200f || c >= 0x202a && c <= 0x202e || c >= 0x2060 && c <= 0x206f || c == 0xfeff || c >= 0xe0000 && c <= 0xe007f
}

func printable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, c := range string(data) {
		if unicode.IsControl(c) && c != '\n' && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}
