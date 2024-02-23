package utils

import "strings"

func curlEscape(s string) string {
	return strings.Replace(s, `"`, `\"`, -1)
}

func BuildCurlConfigFile(d map[string]string) string {
	lines := []string{}
	for k, v := range d {
		lines = append(lines, k+" = \""+curlEscape(v)+"\"")
	}
	return strings.Join(lines, "\n")
}
