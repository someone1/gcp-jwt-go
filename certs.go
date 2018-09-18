package gcpjwt

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pquerna/cachecontrol"
)

const (
	certificateURL = "https://www.googleapis.com/robot/v1/metadata/x509/"
)

// certificates is a map of key id -> public keys
type certificates map[string]*rsa.PublicKey

func getCertificates(ctx context.Context, config *IAMConfig) (certificates, error) {
	if config.EnableCache {
		if certsResp, ok := getCertsFromCache(config.ServiceAccount); ok {
			return certsResp, nil
		}
	}

	// Default config.Client is a http.DefaultClient
	client := config.Client
	if client == nil {
		client = getDefaultClient(ctx)
	}

	req, err := http.NewRequest(http.MethodGet, certificateURL+config.ServiceAccount, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	certsRaw := make(map[string]string)
	err = json.Unmarshal(b, &certsRaw)
	if err != nil {
		return nil, err
	}

	_, expires, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{PrivateCache: true})
	if err != nil && config.CacheExpiration > 0 {
		expires = time.Now().Add(config.CacheExpiration)
	}

	certs := make(certificates)
	for key, cert := range certsRaw {
		rsaKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		if err != nil {
			return nil, err
		}
		certs[key] = rsaKey
	}

	if config.EnableCache && !expires.IsZero() {
		updateCache(config.ServiceAccount, certs, expires)
	}

	return certs, nil
}
