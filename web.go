// vim:ft=go:foldmethod=marker:foldmarker=[[[,]]]
package main

// import [[[
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
) // ]]]

// typedefs [[[

type SSOConfig struct {
	port     int
	IPHeader string
	pubkey   crypto.PublicKey
	privkey  *ecdsa.PrivateKey
}

type SSOCookiePayload struct {
	U string // Username
}

type SSOCookie struct {
	R big.Int          // ECDSA-Signature R
	S big.Int          // ECDSA-Signature S
	H []byte           // Hash over payload and expiry
	E int32            // Expiry timestamp
	P SSOCookiePayload // Payload
}

// ]]]

func readEcPublicKeyPem(filename string) (interface{}, error) { // [[[
	dat, err := ioutil.ReadFile(filename)
	check(err)

	pemblock, _ := pem.Decode(dat)

	config.pubkey, err = x509.ParsePKIXPublicKey(pemblock.Bytes)
	check(err)

	fmt.Println(config.pubkey)

	return config.pubkey, err
} // ]]]

func readEcPrivateKeyPem(filename string) (*ecdsa.PrivateKey, error) { // [[[
	dat, err := ioutil.ReadFile(filename)
	check(err)

	pemblock, _ := pem.Decode(dat)

	config.privkey, err = x509.ParseECPrivateKey(pemblock.Bytes)
	check(err)

	//bytes, err := x509.MarshalECPrivateKey(config.privkey)
	check(err)

	config.pubkey = config.privkey.Public()

	//block := pem.Block{}
	//block.Bytes = bytes
	//block.Type = "EC PRIVATE KEY"
	//bytes_encoded := pem.EncodeToMemory(&block)
	//fmt.Println(string(bytes_encoded))

	//bytes, _ = x509.MarshalPKIXPublicKey(config.pubkey)
	//block = pem.Block{}
	//block.Type = "EC PUBLIC KEY"

	//block.Bytes = bytes
	//bytes_encoded = pem.EncodeToMemory(&block)

	//fmt.Println(string(bytes_encoded))

	return config.privkey, err
} // ]]]

func auth_handler(w http.ResponseWriter, r *http.Request) { // [[[

	// TODO: Also create function ParseCookie
	cookie_string, err := r.Cookie("sso")
	if err != nil {
		log.Printf(">> No sso cookie")
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	log.Printf("IP Header: %s\n", config.IPHeader)
	val, ok := r.Header[config.IPHeader]
	if !ok {
		log.Printf(">> X-Real-Ip missing")
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	} else {
		log.Printf(">> Remote IP %s\n", val[0])
	}

	json_string, _ := url.QueryUnescape(cookie_string.Value)
	log.Printf("%s\n", json_string)
	sso_cookie := new(SSOCookie)

	err = json.Unmarshal([]byte(json_string), &sso_cookie)
	if err != nil {
		fmt.Println("Error unmarshaling JSON: ", err)
		http.Error(w, "Error", http.StatusUnauthorized)
		return
	}

	// Print remote address and UTC-adjusted timestamp in RFC3339 (profile of ISO 8601)
	log.Printf(">> New auth request from %s at %s \n", val[0], time.Now().UTC().Format(time.RFC3339))

	if VerifyCookie(val[0], sso_cookie) {
		fmt.Fprintf(w, "You have been logged in!\n")
		w.Header().Set("REMOTE-USER", sso_cookie.P.U)
		log.Printf(">> Login by %s\n", sso_cookie.P.U)
		return
	} else {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

} // ]]]

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

func VerifyCookie(ip string, sso_cookie *SSOCookie) bool { // [[[

	if int32(time.Now().Unix()) > sso_cookie.E {
		log.Printf(">> sso_cookie expired at %d\n", sso_cookie.E)
		return false
	}

	slice := CreateHash(ip, sso_cookie)
	log.Printf(">> Hash over IP, Expires and Payload: %x\n", slice)

	sign_ok := ecdsa.Verify(config.pubkey.(*ecdsa.PublicKey), slice, &sso_cookie.R, &sso_cookie.S)
	log.Printf(">> Signature over hash: %t\n", sign_ok)
	if !sign_ok {
		return false
	}

	return true
} // ]]]

func CreateCookie(ip string, payload *SSOCookiePayload) string { // [[[

	//expiration := time.Now().Add(365 * 24 * time.Hour)
	expiration := time.Now().Add(10 * time.Second)
	expire := int32(expiration.Unix())

	sso_cookie := new(SSOCookie)
	sso_cookie.E = expire
	sso_cookie.P = *payload
	slice := CreateHash(ip, sso_cookie)

	log.Printf(">> Hash over IP, Expires and Payload: %x\n", slice)

	er, es, _ := ecdsa.Sign(rand.Reader, config.privkey, slice)
	log.Printf(">> Signature over hash: %#v, %#v\n", er, es)

	sso_cookie.R = *er
	sso_cookie.S = *es
	sso_cookie.H = slice

	json_string, _ := json.Marshal(sso_cookie)
	url_string := url.QueryEscape(string(json_string))
	log.Printf("%d bytes: %s\n", len(json_string), json_string)
	log.Printf("%d bytes: %s\n", len(url_string), url_string)

	return url_string
} // ]]]

func login_handler(w http.ResponseWriter, r *http.Request) { // [[[
	// This is how you get request headers
	val, ok := r.Header["X-Real-Ip"]
	if ok {
		log.Printf(">> Remote IP %s\n", val[0])
	}

	// Print remote address and UTC-adjusted timestamp in RFC3339 (profile of ISO 8601)
	log.Printf(">> New login request from %s at %s \n", r.RemoteAddr, time.Now().UTC().Format(time.RFC3339))

	// Iterate over all headers
	for key, value := range r.Header {
		log.Printf(">> %s: %s\n", key, strings.Join(value, ""))
	}

	sso_cookie_payload := new(SSOCookiePayload)
	sso_cookie_payload.U = "jg123456"

	expiration := time.Now().Add(365 * 24 * time.Hour)
	url_string := CreateCookie(val[0], sso_cookie_payload)
	cookie := http.Cookie{Name: "sso", Value: url_string, Expires: expiration}
	http.SetCookie(w, &cookie)

	fmt.Fprintf(w, "You have been logged in!\n")
} // ]]]

func check(e error) { // [[[
	if e != nil {
		panic(e)
	}
} // ]]]

func RegisterHandlers() { // [[[
	http.HandleFunc("/login", login_handler)
	http.HandleFunc("/auth", auth_handler)
} // ]]]

func ParseArgs() { // [[[
	_ = flag.String("pubkey", "prime256v1-public.pem", "Filename of PEM-encoded ECC public key")
	//_, err := readEcPublicKeyPem("prime256v1-public.pem")
	//check(err)

	privatekeyfile := flag.String("privkey", "prime256v1-key.pem", "Filename of PEM-encoded ECC private key")
	_, err := readEcPrivateKeyPem(*privatekeyfile)
	check(err)

	flag.StringVar(&config.IPHeader, "real-ip", "X-Real-Ip", "Name of X-Real-IP Header")
	flag.IntVar(&config.port, "port", 8080, "Listening port")
	flag.Parse()
} // ]]]

var config = new(SSOConfig)

func main() { // [[[
	RegisterHandlers()

	ParseArgs()

	log.Printf(">> Server running on :%d\n", config.port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.port), nil))
} // ]]]
