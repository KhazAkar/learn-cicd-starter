package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

type malformedAuthError struct{}

func (malformedAuthError) Error() string {
	return "malformed authorization header"
}

func (malformedAuthError) Is(target error) bool {
	return target.Error() == "malformed authorization header"
}

var ErrMalformedAuthHeader = malformedAuthError{}

func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "ApiKey" || strings.TrimSpace(parts[1]) == "" {
		return "", ErrMalformedAuthHeader
	}

	return parts[1], nil
}
