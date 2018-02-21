package gcp_jwt

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pquerna/cachecontrol"
)

const (
	certificateURL = "https://www.googleapis.com/robot/v1/metadata/x509/"
)

type certResponse struct {
	certs   certificates
	expires time.Time
}

type certificates map[string]string

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

	certs := make(certificates)

	err = json.Unmarshal(b, &certs)
	if err != nil {
		return nil, err
	}
	_, expires, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{PrivateCache: true})

	return &certResponse{certs, expires}, err
}

func verifyWithCerts(sig, hash []byte, certs certificates) error {
	var certErr error
	for _, cert := range certs {
		certErr = verifyWithCert(sig, hash, cert)
		if certErr == nil {
			break
		}
	}

	return certErr
}

func verifyWithCert(sig, hash []byte, cert string) error {
	rsaKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash, sig)
}
