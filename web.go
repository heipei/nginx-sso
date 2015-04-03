package main

import (
	"crypto"
	"crypto/ecdsa"
	//	"crypto/elliptic"
	//	"crypto/rand"
	//"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var config struct {
	pubkey  crypto.PublicKey
	privkey *ecdsa.PrivateKey
}

func readEcPublicKeyPem(filename string) (interface{}, error) {
	dat, err := ioutil.ReadFile(filename)
	check(err)

	pemblock, _ := pem.Decode(dat)

	config.pubkey, err = x509.ParsePKIXPublicKey(pemblock.Bytes)
	check(err)

	fmt.Println(config.pubkey)

	return config.pubkey, err
}

func readEcPrivateKeyPem(filename string) (*ecdsa.PrivateKey, error) {
	dat, err := ioutil.ReadFile(filename)
	check(err)

	pemblock, _ := pem.Decode(dat)

	config.privkey, err = x509.ParseECPrivateKey(pemblock.Bytes)
	check(err)

	bytes, err := x509.MarshalECPrivateKey(config.privkey)
	check(err)

	block := pem.Block{}
	block.Bytes = bytes
	block.Type = "EC PRIVATE KEY"
	bytes_encoded := pem.EncodeToMemory(&block)
	fmt.Println(string(bytes_encoded))

	config.pubkey = config.privkey.Public()

	bytes, _ = x509.MarshalPKIXPublicKey(config.pubkey)
	block = pem.Block{}
	block.Type = "EC PUBLIC KEY"

	block.Bytes = bytes
	bytes_encoded = pem.EncodeToMemory(&block)

	fmt.Println(string(bytes_encoded))

	return config.privkey, err
}

type ssoCookiePayload struct {
	U string // Username
}

type ssoCookie struct {
	R big.Int          // ECDSA-Signature R
	S big.Int          // ECDSA-Signature S
	H []byte           // Hash over payload and expiry
	E int32            // Expiry timestamp
	P ssoCookiePayload // Payload
}

func auth_handler(w http.ResponseWriter, r *http.Request) {
	cookie_string, _ := r.Cookie("sso")
	json_string, _ := url.QueryUnescape(cookie_string.Value)
	fmt.Printf("%s\n", json_string)
	sso_cookie := new(ssoCookie)

	err := json.Unmarshal([]byte(json_string), &sso_cookie)
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Printf("%#v\n", sso_cookie.R)

	// This is how you set the status code and return immediately
	// w.WriteHeader(404)

	// Send an error
	//http.Error(w, "Error xyz", http.StatusUnauthorized)

	// This is how you set response headers
	w.Header().Set("REMOTE-USER", sso_cookie.P.U)
	fmt.Printf(">> Login by %s\n", sso_cookie.P.U)

	// This is how you get request headers
	val, ok := r.Header["X-Real-Ip"]
	if ok {
		fmt.Printf("Remote IP %s\n", val[0])
	}

	// Print remote address and UTC-adjusted timestamp in RFC3339 (profile of ISO 8601)
	fmt.Printf(">> New auth request from %s at %s \n", val[0], time.Now().UTC().Format(time.RFC3339))

	verified := VerifyCookie(val[0], sso_cookie)
	fmt.Printf("%s\n", verified)

}

func VerifyCookie(ip string, sso_cookie *ssoCookie) string {

	// Create hash, slice it, pass it to sign (including rand reader)
	hash := sha1.New()
	hash.Write([]byte(ip))
	hash.Write([]byte(fmt.Sprintf("%d", sso_cookie.E)))
	hash.Write([]byte(sso_cookie.P.U))
	sum := hash.Sum(nil)
	slice := sum[:]

	fmt.Printf(">> Hash over IP, Expires and Payload: %x\n", slice)

	sign_ok := ecdsa.Verify(config.pubkey.(*ecdsa.PublicKey), slice, &sso_cookie.R, &sso_cookie.S)
	fmt.Printf(">> Signature over hash: %t\n", sign_ok)

	return "ok"
}

func CreateCookie(ip string, payload *ssoCookiePayload) string {

	expiration := time.Now().Add(365 * 24 * time.Hour)
	expire := int32(expiration.Unix())

	// Create hash, slice it, pass it to sign (including rand reader)
	hash := sha1.New()
	hash.Write([]byte(ip))
	hash.Write([]byte(fmt.Sprintf("%d", expire)))
	hash.Write([]byte(payload.U))
	sum := hash.Sum(nil)
	slice := sum[:]

	fmt.Printf(">> Hash over IP, Expires and Payload: %x\n", slice)

	er, es, _ := ecdsa.Sign(rand.Reader, config.privkey, slice)
	fmt.Printf(">> Signature over hash: %#v, %#v\n", er, es)

	sso_cookie := new(ssoCookie)
	sso_cookie.R = *er
	sso_cookie.S = *es
	sso_cookie.H = slice
	sso_cookie.E = expire
	sso_cookie.P = *payload

	json_string, _ := json.Marshal(sso_cookie)
	url_string := url.QueryEscape(string(json_string))
	fmt.Printf("%d bytes: %s\n", len(json_string), json_string)
	fmt.Printf("%d bytes: %s\n", len(url_string), url_string)

	return url_string
}

func login_handler(w http.ResponseWriter, r *http.Request) {
	// This is how you get request headers
	val, ok := r.Header["X-Real-Ip"]
	if ok {
		fmt.Printf("Remote IP %s\n", val[0])
	}

	// Print remote address and UTC-adjusted timestamp in RFC3339 (profile of ISO 8601)
	fmt.Printf(">> New login request from %s at %s \n", r.RemoteAddr, time.Now().UTC().Format(time.RFC3339))

	// Iterate over all headers
	for key, value := range r.Header {
		fmt.Printf(">> %s: %s\n", key, strings.Join(value, ""))
	}

	sso_cookie_payload := new(ssoCookiePayload)
	sso_cookie_payload.U = "jg123456"

	expiration := time.Now().Add(365 * 24 * time.Hour)
	url_string := CreateCookie(val[0], sso_cookie_payload)
	cookie := http.Cookie{Name: "sso", Value: url_string, Expires: expiration}
	http.SetCookie(w, &cookie)

	fmt.Fprintf(w, "You have been logged in!\n")
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Send an error
	http.Error(w, "Error xyz", http.StatusUnauthorized)
	return
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/login", login_handler)
	http.HandleFunc("/auth", auth_handler)

	//_, err := readEcPublicKeyPem("prime256v1-public.pem")
	//check(err)

	_, err := readEcPrivateKeyPem("prime256v1-key.pem")
	check(err)

	fmt.Printf("Server running\n")
	http.ListenAndServe(":8080", nil)
}
