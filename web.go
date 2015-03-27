package main

import (
	"crypto/ecdsa"
	//	"crypto/elliptic"
	//	"crypto/rand"
	//"bytes"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var config struct {
	pubkey  interface{}
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
	Username string
	Expiry   int64
}

type ssoCookie struct {
	R       *big.Int
	S       *big.Int
	Hash    []byte
	Payload ssoCookiePayload
}

func login_handler(w http.ResponseWriter, r *http.Request) {
	// This is how you get request headers
	if val, ok := r.Header["User-Agent"]; ok {
		fmt.Printf("%s\n", val[0])
	}

	// Get the remote address
	// Print remote address and UTC-adjusted timestamp in RFC3339 (profile of ISO 8601)
	fmt.Printf(">> New login request from %s at %s \n", r.RemoteAddr, time.Now().UTC().Format(time.RFC3339))

	// Create hash, slice it, pass it to sign (including rand reader)
	hash := sha256.Sum256([]byte(r.RemoteAddr))
	slice := hash[:]

	er, es, _ := ecdsa.Sign(rand.Reader, config.privkey, slice)
	fmt.Printf(">> Signature over r.RemoteAddr: %#v, %#v\n", er, es)

	// Hash with printing of []byte via %x
	fmt.Printf(">> Hash over r.RemoteAddr: %x\n", sha256.Sum256([]byte(r.RemoteAddr)))

	// Iterate over all headers
	// Join strings
	for key, value := range r.Header {
		fmt.Printf("%s: %s\n", key, strings.Join(value, ""))
	}

	// This is how you set response headers
	w.Header().Set("Custom-Header", "Jojo")

	// This is how you set the status code and return immediately
	// w.WriteHeader(404)

	// TODO: Have to include remote IP in hash calc as well
	sso_cookie_payload := new(ssoCookiePayload)
	sso_cookie_payload.Username = "Johannes Gilger"
	sso_cookie_payload.Expiry = time.Now().Unix()
	fmt.Printf("%d\n", sso_cookie_payload.Expiry)

	sso_cookie := new(ssoCookie)
	sso_cookie.R = er
	sso_cookie.S = es
	sso_cookie.Hash = slice

	var network bytes.Buffer        // Stand-in for a network connection
	enc := gob.NewEncoder(&network) // Will write to network.

	// Encode (send) some values.
	err := enc.Encode(sso_cookie)
	if err != nil {
		fmt.Printf("encode error: %s\n", err)
	}

	fmt.Printf("%#v\n", network)
	// Setting a cookie in the response
	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := http.Cookie{Name: "username", Value: "astaxie", Expires: expiration}
	http.SetCookie(w, &cookie)

	// TODO: Encode using golang gob (big int already implements interface)
	cookie_string := fmt.Sprintf("h:%sr:%ss:%s", strings.Replace(base64.URLEncoding.EncodeToString(slice), "=", ".", -1), er.String(), es.String())
	cookie = http.Cookie{Name: "sso", Value: cookie_string, Expires: expiration}
	http.SetCookie(w, &cookie)

	fmt.Fprintf(w, "%#v\n", config.pubkey)
	fmt.Fprintf(w, "You have been logged in!\n")
}

func handler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Error xyz", http.StatusUnauthorized)
	return
	fmt.Fprintf(w, "Hi there, I love %s!\n", r.URL.Path[1:])
	fmt.Fprintf(w, "Test123!\n")
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/login", login_handler)

	_, err := readEcPrivateKeyPem("prime256v1-key.pem")
	check(err)

	_, err = readEcPublicKeyPem("prime256v1-public.pem")
	check(err)

	fmt.Printf("Server running\n")
	http.ListenAndServe(":8080", nil)
}
