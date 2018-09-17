package gcpjwt

import (
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

type certResponse struct {
	certs   certificates
	expires time.Time
}

// certificates is a map of key id -> public keys
type certificates map[string]*rsa.PublicKey

func getCertificatesForAccount(hc *http.Client, account string) (*certResponse, error) {
	req, err := http.NewRequest(http.MethodGet, certificateURL+account, nil)
	if err != nil {
		return nil, err
	}

	resp, err := hc.Do(req)
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

	if err != nil {
		return nil, err
	}

	certs := make(certificates)

	for key, cert := range certsRaw {
		rsaKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		if err != nil {
			return nil, err
		}
		certs[key] = rsaKey
	}

	return &certResponse{certs, expires}, err
}
