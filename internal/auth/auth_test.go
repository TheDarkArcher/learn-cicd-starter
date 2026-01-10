package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input       http.Header
		want        string
		expectedErr error
	}{
		"simple":    {input: http.Header{http.CanonicalHeaderKey("Authorization"): {"ApiKey f271c81ff7084ee5b99a5091b42d486e"}}, want: "f271c81ff7084ee5b99a5091b42d486e", expectedErr: nil},
		"malformed": {input: http.Header{http.CanonicalHeaderKey("Authorization"): {"ApiKey"}}, want: "", expectedErr: errors.New("malformed authorization header")},
		"missing":   {input: http.Header{}, want: "", expectedErr: ErrNoAuthHeaderIncluded},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			apiKey, err := GetAPIKey(test.input)
			errString := ""
			if err != nil {
				errString = err.Error()
			}
			expectedErrString := ""
			if test.expectedErr != nil {
				expectedErrString = test.expectedErr.Error()
			}
			if apiKey != test.want || errString != expectedErrString {
				t.Errorf(`---------------------------------
Inputs:     (%v)
Expecting:  (%v, %v)
Actual:     (%v, %v)
Fail
`, test.input, test.want, test.expectedErr, apiKey, err)
			}
		})
	}
}
