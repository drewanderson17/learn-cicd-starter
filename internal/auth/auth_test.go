package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "Valid Authorization Header",
			headers: http.Header{"Authorization": {"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "Missing Authorization Header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed Authorization Header",
			headers: http.Header{"Authorization": {"Bearer my-secret-key"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Empty Authorization Header",
			headers: http.Header{"Authorization": {""}},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Incomplete Authorization Header",
			headers: http.Header{"Authorization": {"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() gotKey = %v, want %v", gotKey, tt.wantKey)
			}

			if gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() gotErr = %v, want %v", gotErr, tt.wantErr)
			} else if (gotErr != nil && tt.wantErr == nil) || (gotErr == nil && tt.wantErr != nil) {
				t.Errorf("GetAPIKey() unexpected error: gotErr = %v, wantErr = %v", gotErr, tt.wantErr)
			}
		})
	}
}
