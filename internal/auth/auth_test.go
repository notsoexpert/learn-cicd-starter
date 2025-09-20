package auth

import (
	"testing"
	"net/http"
    "strings"
)

func TestGetAPIKey(t *testing.T) {
    type headerSet struct {
        header string
        key string
    }
    type test struct {
        setHeader *headerSet
        want string
    }

    tests := []test{}
        {setHeader: nil, want: ""},
        {setHeader: &headerSet{header: "Authorization", key: "Bearer sometoken"}, want: ""},
        {setHeader: &headerSet{header: "Authorization", key: "ApiKey my-secret-key"}, want: "my-secret-key"},
    }

    for _, tc := range tests {
        request, _ := http.NewRequest("GET", "/", nil)
        if tc.setHeader != nil {
            request.Header.Set(tc.setHeader.header, tc.setHeader.key)
        }
        apiKey, err := GetAPIKey(request.Header)

        if apiKey != tc.want {
            t.Errorf("expected %s for apiKey, got %q", tc.want, apiKey)
        }
        if tc.setHeader == nil {
            if err != ErrNoAuthHeaderIncluded {
                t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
            }
            return;
        }
        if !strings.Contains(tc.setHeader.key, "ApiKey") {
            if err == nil || err.Error() != "malformed authorization header" {
                t.Errorf("expected malformed authorization header error, got %v", err)
            }
        }
        if err != nil {
            t.Errorf("expected no error, got %v", err)
        }
    }
}