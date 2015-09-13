// vim:ft=go:foldmethod=indent:foldnestmax=1

// ssocookie - Functions for handling login and auth using the SSO cookie
//
// This package implements functions that can be used both by the SSO cookie
// login service as well as the SSO cookie auth service.
//
// (c) 2015 by Johannes Gilger <heipei@hackvalue.de>

package ssocookie

// imports
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"math/big"
	"net/url"
	"time"
)

// typedefs

type CookiePayload struct {
	U string // Username string
	G string // Group string
}

type Cookie struct {
	R big.Int       // ECDSA-Signature R
	S big.Int       // ECDSA-Signature S
	E int32         // Expiry timestamp
	P CookiePayload // Payload
}

func CreateHash(ip string, sso_cookie *Cookie) []byte {

	// Create hash, slice it
	hash := sha1.New()
	hash.Write([]byte(ip))
	hash.Write([]byte(fmt.Sprintf("%d", sso_cookie.E)))

	// TODO: Convert arbitrary JSON to []byte
	hash.Write([]byte(sso_cookie.P.U))
	hash.Write([]byte(sso_cookie.P.G))
	sum := hash.Sum(nil)
	slice := sum[:]
	return slice
}

func CreateCookie(ip string, payload *CookiePayload, privkey *ecdsa.PrivateKey, expiry time.Duration) string {

	expiration := time.Now().Add(expiry)
	expire := int32(expiration.Unix())

	sso_cookie := new(Cookie)
	sso_cookie.E = expire
	sso_cookie.P = *payload
	slice := CreateHash(ip, sso_cookie)

	log.Debugf("Hash over IP, Expires and Payload: %x", slice)

	er, es, _ := ecdsa.Sign(rand.Reader, privkey, slice)
	log.Debugf("Signature over hash: %#v, %#v", er, es)

	sso_cookie.R = *er
	sso_cookie.S = *es

	json_string, _ := json.Marshal(sso_cookie)
	url_string := url.QueryEscape(string(json_string))
	log.Debugf("%d bytes: %s", len(json_string), json_string)
	log.Debugf("%d bytes: %s", len(url_string), url_string)

	return url_string
}

func VerifyCookie(ip string, sso_cookie *Cookie, pubkey *ecdsa.PublicKey) bool {

	if int32(time.Now().Unix()) > sso_cookie.E {
		log.Infof("sso_cookie expired at %d", sso_cookie.E)
		return false
	}

	slice := CreateHash(ip, sso_cookie)
	log.Debugf("Hash over IP, Expires and Payload: %x", slice)

	log.Debugf("R: %#v, S: %#v", &sso_cookie.R, &sso_cookie.S)
	sign_ok := ecdsa.Verify(pubkey, slice, &sso_cookie.R, &sso_cookie.S)
	log.Debugf("Signature over hash: %t", sign_ok)
	if !sign_ok {
		return false
	}

	return true
}

func ReadECCPublicKeyPem(filename string, Pubkey crypto.PublicKey) (interface{}, error) {
	dat, err := ioutil.ReadFile(filename)
	CheckError(err)

	pemblock, _ := pem.Decode(dat)

	Pubkey, err = x509.ParsePKIXPublicKey(pemblock.Bytes)
	CheckError(err)

	PrintPublicKey(Pubkey)

	return Pubkey, err
}

func ReadECCPrivateKeyPem(filename string) (*ecdsa.PrivateKey, error) {
	dat, err := ioutil.ReadFile(filename)
	CheckError(err)

	pemblock, _ := pem.Decode(dat)

	privkey, err := x509.ParseECPrivateKey(pemblock.Bytes)
	CheckError(err)

	//bytes, err := x509.MarshalECPrivateKey(config.privkey)
	CheckError(err)

	//config.Pubkey = config.Privkey.Public()

	//PrintPublicKey(config.Pubkey)

	//block := pem.Block{}
	//block.Bytes = bytes
	//block.Type = "EC PRIVATE KEY"
	//bytes_encoded := pem.EncodeToMemory(&block)
	//fmt.Println(string(bytes_encoded))

	return privkey, err
}

func PrintPublicKey(pubkey crypto.PublicKey) {

	bytes, _ := x509.MarshalPKIXPublicKey(pubkey)
	block := pem.Block{}
	block.Type = "EC PUBLIC KEY"

	block.Bytes = bytes
	bytes_encoded := pem.EncodeToMemory(&block)

	log.Debugf("Public key:\n%s", string(bytes_encoded))
}

func CheckError(e error) {
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
}
