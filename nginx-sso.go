// vim:ft=go:foldmethod=marker:foldmarker=[[[,]]]
package main

// imports [[[
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/heipei/nginx-sso/ssocookie"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
) // ]]]

// typedefs [[[

type AuthenticateFunc func(r *http.Request) string

type SSOConfig struct {
	port         int
	IPHeader     string
	pubkey       crypto.PublicKey
	privkey      *ecdsa.PrivateKey
	Authenticate AuthenticateFunc
}

// ]]]

func ReadECCPublicKeyPem(filename string, config *SSOConfig) (interface{}, error) { // [[[
	dat, err := ioutil.ReadFile(filename)
	CheckError(err)

	pemblock, _ := pem.Decode(dat)

	config.pubkey, err = x509.ParsePKIXPublicKey(pemblock.Bytes)
	CheckError(err)

	fmt.Println(config.pubkey)

	return config.pubkey, err
} // ]]]

func ReadECCPrivateKeyPem(filename string, config *SSOConfig) (*ecdsa.PrivateKey, error) { // [[[
	dat, err := ioutil.ReadFile(filename)
	CheckError(err)

	pemblock, _ := pem.Decode(dat)

	config.privkey, err = x509.ParseECPrivateKey(pemblock.Bytes)
	CheckError(err)

	//bytes, err := x509.MarshalECPrivateKey(config.privkey)
	CheckError(err)

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

func AuthHandler(config *SSOConfig) http.Handler { // [[[
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// TODO: Also create function ParseCookie
		cookie_string, err := r.Cookie("sso")
		if err != nil {
			log.Infof(">> No sso cookie")
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}

		log.Infof("IP Header: %s", config.IPHeader)
		ip := r.Header.Get(config.IPHeader)
		if ip == "" {
			log.Infof(">> Header %s missing", config.IPHeader)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		} else {
			log.Infof(">> Remote IP %s", ip)
		}

		json_string, _ := url.QueryUnescape(cookie_string.Value)
		log.Infof("%s", json_string)
		sso_cookie := new(ssocookie.SSOCookie)

		err = json.Unmarshal([]byte(json_string), &sso_cookie)
		if err != nil {
			fmt.Println("Error unmarshaling JSON: ", err)
			http.Error(w, "Error", http.StatusUnauthorized)
			return
		}

		// Print remote address and UTC-adjusted timestamp in RFC3339
		// (profile of ISO 8601)
		log.Infof(">> New auth request from %s at %s ", ip,
			time.Now().UTC().Format(time.RFC3339))

		if ssocookie.VerifyCookie(ip, sso_cookie,
			config.pubkey.(*ecdsa.PublicKey)) {

			w.Header().Set("Remote-User", sso_cookie.P.U)
			w.Header().Set("Remote-Expiry", fmt.Sprintf("%d",
				sso_cookie.E))
			fmt.Fprintf(w, "Authorized!\n")
			log.Infof(">> Login by %s", sso_cookie.P.U)
			return
		} else {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
	})

} // ]]]

func CheckError(e error) { // [[[
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
} // ]]]

func RegisterHandlers(config *SSOConfig) { // [[[
	http.Handle("/login", LoginHandler(config))
	http.Handle("/auth", AuthHandler(config))
} // ]]]

func ParseArgs(config *SSOConfig) { // [[[
	_ = flag.String("pubkey", "prime256v1-public.pem", "Filename of PEM-encoded ECC public key")
	//_, err := ReadECCPublicKeyPem("prime256v1-public.pem")
	//CheckError(err)

	privatekeyfile := flag.String("privkey", "prime256v1-key.pem", "Filename of PEM-encoded ECC private key")

	flag.StringVar(&config.IPHeader, "real-ip", "X-Real-Ip", "Name of X-Real-IP Header")
	flag.IntVar(&config.port, "port", 8080, "Listening port")
	flag.Parse()

	_, err := ReadECCPrivateKeyPem(*privatekeyfile, config)
	CheckError(err)
	log.Infof(">> Read ECC private key from %s", *privatekeyfile)

	config.Authenticate = AuthenticateFunc(Authenticate)
} // ]]]

func main() { // [[[
	config := new(SSOConfig)

	RegisterHandlers(config)

	ParseArgs(config)

	log.Infof(">> Server running on 127.0.0.1:%d", config.port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", config.port), nil))
} // ]]]

// TODO: These two functions go into Login program
func Authenticate(r *http.Request) string { // [[[
	return "jg123456"
} // ]]]

func LoginHandler(config *SSOConfig) http.Handler { // [[[
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is how you get request headers
		ip := r.Header.Get(config.IPHeader)
		if ip == "" {
			log.Infof(">> Header %s missing", config.IPHeader)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		} else {
			log.Infof(">> Remote IP %s", ip)
		}

		// Print remote address and UTC-adjusted timestamp in RFC3339
		// (profile of ISO 8601)
		log.Infof(">> New login request from %s at %s ", r.RemoteAddr,
			time.Now().UTC().Format(time.RFC3339))

		// Iterate over all headers
		for key, value := range r.Header {
			log.Infof(">> %s: %s", key, strings.Join(value, ""))
		}

		sso_cookie_payload := new(ssocookie.SSOCookiePayload)

		// TODO: Pass sso_cookie as parameter to set U and G
		sso_cookie_payload.U = config.Authenticate(r)

		expiration := time.Now().Add(365 * 24 * time.Hour)
		url_string := ssocookie.CreateCookie(ip, sso_cookie_payload,
			config.privkey)
		cookie := http.Cookie{Name: "sso", Value: url_string,
			Expires: expiration}
		http.SetCookie(w, &cookie)

		fmt.Fprintf(w, "You have been logged in!\n")
	})
} // ]]]
