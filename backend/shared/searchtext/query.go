package searchtext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// SQLQuery builds a PostgreSQL tsquery using text and prefix parameters $2 and $3.
const SQLQuery = `(CASE WHEN $3::text = '' THEN plainto_tsquery('simple', $2)
	ELSE plainto_tsquery('simple', $2) && to_tsquery('simple', $3 || ':*') END)`

func Valid(query, prefix string) bool {
	if len(query)+len(prefix) > 256 || !utf8.ValidString(query) || strings.ContainsRune(query, 0) {
		return false
	}

	if prefix == "" {
		return strings.TrimSpace(query) != ""
	}

	return len(prefix) <= 64 && utf8.RuneCountInString(prefix) >= 2 &&
		utf8.ValidString(prefix) && strings.IndexFunc(prefix, isSeparator) < 0
}

func SplitPrefix(query string) (string, string, bool) {
	if !Valid(query, "") {
		return "", "", false
	}

	query = strings.TrimSpace(query)
	start := 0
	for index, character := range query {
		if isSeparator(character) {
			start = index + utf8.RuneLen(character)
		}
	}

	complete, prefix := strings.TrimSpace(query[:start]), query[start:]
	return complete, prefix, prefix != "" && Valid(complete, prefix)
}

func isSeparator(character rune) bool {
	return !unicode.IsLetter(character) && !unicode.IsNumber(character)
}
