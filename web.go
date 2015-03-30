package main

import (
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
	U string
}

type ssoCookie struct {
	R big.Int
	S big.Int
	H []byte
	E int32
	I string
	P ssoCookiePayload
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
	fmt.Printf("%s\n", sso_cookie)
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
	hash := sha1.Sum([]byte(r.RemoteAddr))
	slice := hash[:]

	er, es, _ := ecdsa.Sign(rand.Reader, config.privkey, slice)
	fmt.Printf(">> Signature over r.RemoteAddr: %#v, %#v\n", er, es)

	// H with printing of []byte via %x
	fmt.Printf(">> H over r.RemoteAddr: %x\n", sha1.Sum([]byte(r.RemoteAddr)))

	// Iterate over all headers
	// Join strings
	for key, value := range r.Header {
		fmt.Printf("%s: %s\n", key, strings.Join(value, ""))
	}

	// This is how you set response headers
	w.Header().Set("Custom-Header", "Jojo")

	// This is how you set the status code and return immediately
	// w.WriteHeader(404)

	expiration := time.Now().Add(365 * 24 * time.Hour)
	sso_cookie_payload := new(ssoCookiePayload)
	sso_cookie_payload.U = "jg123456"

	sso_cookie := new(ssoCookie)
	sso_cookie.R = *er
	sso_cookie.S = *es
	sso_cookie.P = *sso_cookie_payload
	sso_cookie.H = slice
	sso_cookie.E = int32(expiration.Unix())
	sso_cookie.I = r.RemoteAddr // FIXME: Hash over request-header with X-Real-IP

	fmt.Printf("%d\n", sso_cookie.E)

	//var network bytes.Buffer        // Stand-in for a network connection
	//enc := gob.NewEncoder(&network) // Will write to network.

	// Encode (send) some values.
	//err := enc.Encode(sso_cookie)
	//if err != nil {
	//	fmt.Printf("encode error: %s\n", err)
	//}
	json_string, _ := json.Marshal(sso_cookie)
	url_string := url.QueryEscape(string(json_string))
	fmt.Printf("%d bytes: %s\n", len(json_string), json_string)
	fmt.Printf("%d bytes: %s\n", len(url_string), url_string)

	//json_string_bytes := base64.URLEncoding.EncodeToString([]byte(json_string))
	//fmt.Printf("%d bytes: %s\n", len(json_string_bytes), json_string_bytes)

	//fmt.Printf("%v\n", network)

	// Setting a cookie in the response
	//cookie := http.Cookie{Name: "username", Value: "astaxie", Expires: expiration}
	//http.SetCookie(w, &cookie)

	cookie := http.Cookie{Name: "sso", Value: url_string, Expires: expiration}
	http.SetCookie(w, &cookie)

	// Setting the cookie to the base64-encoded gob-encoded struct
	//ssocookie_string := base64.URLEncoding.EncodeToString(network.Bytes())
	//ssocookie_string = strings.Replace(ssocookie_string, "=", ".", -1)
	//fmt.Printf("ssocookie size is %d\n", len(ssocookie_string))
	//cookie = http.Cookie{Name: "ssocookie", Value: ssocookie_string, Expires: expiration}
	//http.SetCookie(w, &cookie)

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
	http.HandleFunc("/auth", auth_handler)

	_, err := readEcPrivateKeyPem("prime256v1-key.pem")
	check(err)

	_, err = readEcPublicKeyPem("prime256v1-public.pem")
	check(err)

	fmt.Printf("Server running\n")
	http.ListenAndServe(":8080", nil)
}
