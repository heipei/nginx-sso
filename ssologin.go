// vim:ft=go:foldmethod=indent:foldnestmax=1

// ssologin - Login (create) SSO cookie
//
// (c) 2015 by Johannes Gilger <heipei@hackvalue.de>
package main

// imports [[[
import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/heipei/nginx-sso/ssocookie"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	Port    int
	Headers struct {
		Ip string
	}
	Privkey *ecdsa.PrivateKey
	Expiry  time.Duration
	Domain  string
	Secure  bool
	Debug   bool
}

func Authenticate(r *http.Request) string {
	return "jg123456"
}

func LoginHandler(config *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip := r.Header.Get(config.Headers.Ip)
		if ip == "" {
			log.Warnf("Header %s missing", config.Headers.Ip)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		} else {
			log.Infof("Remote IP %s", ip)
		}

		// Print remote address and UTC-adjusted timestamp in RFC3339
		// (profile of ISO 8601)
		log.Infof("New login request from %s at %s ", r.RemoteAddr,
			time.Now().UTC().Format(time.RFC3339))

		// Iterate over all headers
		for key, value := range r.Header {
			log.Debugf("%s: %s", key, strings.Join(value, ""))
		}

		sso_cookie_payload := new(ssocookie.CookiePayload)

		// TODO: Pass sso_cookie as parameter to set U and G
		sso_cookie_payload.U = Authenticate(r)
		sso_cookie_payload.G = "x:engineering"

		expiration := time.Now().Add(config.Expiry)
		url_string := ssocookie.CreateCookie(ip, sso_cookie_payload,
			config.Privkey, config.Expiry)
		// TODO: Add domain / path / secure / HTTP Only
		cookie := http.Cookie{Name: "sso", Value: url_string,
			Expires: expiration, Secure: false, Domain: ".domain.dev"}
		http.SetCookie(w, &cookie)

		fmt.Fprintf(w, "You have been logged in!\n")
	})
}

func RegisterHandlers(config *Config) {
	http.Handle("/login", LoginHandler(config))
}

func ParseArgs(config *Config) {
	debug := flag.Bool("debug", false, "Debug-level output")
	privatekeyfile := flag.String("privkey", "prime256v1-key.pem", "Filename of PEM-encoded ECC private key")

	flag.StringVar(&config.Headers.Ip, "real-ip", "X-Real-Ip", "Name of X-Real-IP Header")
	flag.IntVar(&config.Port, "port", 8080, "Listening port")
	flag.DurationVar(&config.Expiry, "expiry", 3600*time.Second, "Cookie expiry time (seconds)")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	privkey, err := ssocookie.ReadECCPrivateKeyPem(*privatekeyfile)
	CheckError(err)
	config.Privkey = privkey
	log.Infof("Read ECC private key from %s", *privatekeyfile)
}

func main() {
	log.Infof("ssologin starting")

	config := new(Config)

	RegisterHandlers(config)

	ParseArgs(config)

	log.Infof("ssologin server running on 127.0.0.1:%d", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", config.Port), nil))
}

func CheckError(e error) {
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
}
