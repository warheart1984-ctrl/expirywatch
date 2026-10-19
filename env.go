package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// expandEnv replaces ${NAME} with the value of the environment variable NAME.
// Only the braced form is expanded, so a lone "$" or "$NAME" stays literal,
// and "$${" is an escape for a literal "${". A referenced variable that is
// unset or empty is an error, since an empty URL is never what was meant.
func expandEnv(s string) (string, error) {
	if !strings.Contains(s, "$") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("${")
			i += 2
			continue
		}
		if !strings.HasPrefix(s[i:], "${") {
			b.WriteByte('$')
			continue
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated ${ in %q", s)
		}
		name := s[i+2 : i+2+end]
		if !validEnvName(name) {
			return "", fmt.Errorf("invalid variable name %q", name)
		}
		value, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		if value == "" {
			return "", fmt.Errorf("environment variable %s is empty", name)
		}
		b.WriteString(value)
		i += 2 + end
	}
	return b.String(), nil
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// withoutURL drops the request URL from an *url.Error so that secrets
// expanded into a URL don't end up in error output.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s request: %w", ue.Op, ue.Err)
	}
	return err
}
