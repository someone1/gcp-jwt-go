package gcp_jwt

import (
	"time"

	cache "github.com/patrickmn/go-cache"
)

var (
	certsCache *cache.Cache
)

func init() {
	// We will set expiration time of items and evict on every refresh
	certsCache = cache.New(0, 0)
}

func getCertFromCache(serviceAccount, keyID string) (string, bool) {
	certs, found := getCertsFromCache(serviceAccount)
	if !found {
		return "", false
	}

	cert, found := certs[keyID]
	return cert, found
}

func getCertsFromCache(serviceAccount string) (certificates, bool) {
	certsObj, found := certsCache.Get(serviceAccount)
	if !found {
		return nil, false
	}

	certs, ok := certsObj.(certificates)
	return certs, ok
}

func updateCache(serviceaccount string, certs certificates, expires time.Time) {
	exp := time.Until(expires)
	certsCache.Set(serviceaccount, certs, exp)

	// Let's try and evict expired items
	certsCache.DeleteExpired()
}
