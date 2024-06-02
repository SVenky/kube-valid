package util

import (
	"regexp"
	"strings"
)

var splitRegex = regexp.MustCompile(`(^|\n)---`)

// SplitString splits the given yaml doc if it's multipart document.
func SplitYamlString(yamlText string) []string {
	out := make([]string, 0)
	parts := splitRegex.Split(yamlText, -1)
	for _, part := range parts {
		part := strings.TrimSpace(part)
		if len(part) > 0 {
			out = append(out, part)
		}
	}
	return out
}
