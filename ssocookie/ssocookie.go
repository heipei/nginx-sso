// vim:ft=go:foldmethod=marker:foldmarker=[[[,]]]
package ssocookie

// imports [[[
import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"math/big"
	"net/url"
	"time"
) // ]]]

// typedefs [[[

type SSOCookiePayload struct {
	U string // Username
	G string // Group string
}

type SSOCookie struct {
	R big.Int          // ECDSA-Signature R
	S big.Int          // ECDSA-Signature S
	E int32            // Expiry timestamp
	P SSOCookiePayload // Payload
}

// ]]]

func CreateHash(ip string, sso_cookie *SSOCookie) []byte { // [[[
	// Create hash, slice it
	hash := sha1.New()
	hash.Write([]byte(ip))
	hash.Write([]byte(fmt.Sprintf("%d", sso_cookie.E)))
	hash.Write([]byte(sso_cookie.P.U))
	sum := hash.Sum(nil)
	slice := sum[:]
	return slice
} // ]]]

func CreateCookie(ip string, payload *SSOCookiePayload, privkey *ecdsa.PrivateKey) string { // [[[

	//expiration := time.Now().Add(365 * 24 * time.Hour)
	expiration := time.Now().Add(10 * time.Second)
	expire := int32(expiration.Unix())

	sso_cookie := new(SSOCookie)
	sso_cookie.E = expire
	sso_cookie.P = *payload
	slice := CreateHash(ip, sso_cookie)

	log.Infof(">> Hash over IP, Expires and Payload: %x", slice)

	er, es, _ := ecdsa.Sign(rand.Reader, privkey, slice)
	log.Infof(">> Signature over hash: %#v, %#v", er, es)

	sso_cookie.R = *er
	sso_cookie.S = *es

	json_string, _ := json.Marshal(sso_cookie)
	url_string := url.QueryEscape(string(json_string))
	log.Infof("%d bytes: %s", len(json_string), json_string)
	log.Infof("%d bytes: %s", len(url_string), url_string)

	return url_string
} // ]]]

func VerifyCookie(ip string, sso_cookie *SSOCookie, pubkey *ecdsa.PublicKey) bool { // [[[

	if int32(time.Now().Unix()) > sso_cookie.E {
		log.Infof(">> sso_cookie expired at %d", sso_cookie.E)
		return false
	}

	slice := CreateHash(ip, sso_cookie)
	log.Infof(">> Hash over IP, Expires and Payload: %x", slice)

	sign_ok := ecdsa.Verify(pubkey, slice, &sso_cookie.R, &sso_cookie.S)
	log.Infof(">> Signature over hash: %t", sign_ok)
	if !sign_ok {
		return false
	}

	return true
} // ]]]
