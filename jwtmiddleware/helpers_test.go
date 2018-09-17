package jwtmiddleware

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gjwt "golang.org/x/oauth2/jwt"

	"github.com/someone1/gcp-jwt-go"
	goauth2 "github.com/someone1/gcp-jwt-go/oauth2"
)

var jwtConfig *gjwt.Config

func init() {
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		panic("GOOGLE_APPLICATION_CREDENTIALS environmental variable required for this test to run!")
	}

	b, err := ioutil.ReadFile(credPath)
	if err != nil {
		panic(err)
	}

	jwtConfig, err = google.JWTConfigFromJSON(b)
	if err != nil {
		panic(err)
	}
}

func TestHelpers(t *testing.T) {
	ctx := context.Background()
	config := &gcpjwt.IAMConfig{
		ServiceAccount: jwtConfig.Email,
	}
	config.EnableCache = true
	audience := "https://test.com"
	testSources := make(map[int]oauth2.TokenSource)

	t.Run("TokenSource", func(t *testing.T) {
		var tests = []struct {
			name   string
			config *gcpjwt.IAMConfig
			out    bool
		}{
			{
				"no type",
				&gcpjwt.IAMConfig{
					ServiceAccount: jwtConfig.Email,
				},
				true,
			},
			{
				"blob type",
				&gcpjwt.IAMConfig{
					ServiceAccount: jwtConfig.Email,
					IAMType:        gcpjwt.IAMBlobType,
				},
				false,
			},
			{
				"jwt type",
				&gcpjwt.IAMConfig{
					ServiceAccount: jwtConfig.Email,
					IAMType:        gcpjwt.IAMJwtType,
				},
				false,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				source, err := goauth2.JWTAccessTokenSource(ctx, test.config, audience)
				if (err != nil) != test.out {
					t.Errorf("unexpected error `%v`", err)
				}
				if err == nil {
					testSources[int(test.config.IAMType)] = source
				}
			})
		}
	})

	t.Run("JWTMiddleware", func(t *testing.T) {
		okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("ok"))
		})
		handler := NewHandler(ctx, config, "")(okHandler)
		var tests = []struct {
			name   string
			url    string
			source oauth2.TokenSource
			want   int
		}{
			{
				"InvalidHost",
				"http://test.com",
				nil,
				http.StatusForbidden,
			},
			{
				"MissingToken",
				audience,
				nil,
				http.StatusForbidden,
			},
			{
				"BlobToken",
				audience,
				testSources[int(gcpjwt.IAMBlobType)],
				http.StatusOK,
			},
			{
				"JwtToken",
				audience,
				testSources[int(gcpjwt.IAMJwtType)],
				http.StatusOK,
			},
		}
		// Required for this to work
		gcpjwt.OverrideRS256WithIAMJWT()
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				w.Body = bytes.NewBuffer(nil)
				r := httptest.NewRequest(http.MethodGet, test.url, nil)
				if test.source != nil {
					token, err := test.source.Token()
					if err != nil {
						t.Errorf("error getting token: %v", err)
					}
					r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
				}
				handler.ServeHTTP(w, r)
				if got := w.Result().StatusCode; got != test.want {
					t.Errorf("expected response code `%d`, got `%d`", test.want, got)
					t.Errorf("Body: %s", w.Body.String())
				}
			})
		}

	})

}
