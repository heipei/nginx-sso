// vim:ft=go:foldmethod=marker:foldmarker=[[[,]]]

// ssologin - Login (create) SSO cookie
//
// (c) 2015 by Johannes Gilger <heipei@hackvalue.de>
package main

// imports [[[
import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/heipei/nginx-sso/ssocookie"
	"net/http"
	"strings"
	"time"
) // ]]]

func Authenticate(r *http.Request) string { // [[[
	return "jg123456"
} // ]]]

func LoginHandler(config *ssocookie.Config) http.Handler { // [[[
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

		sso_cookie_payload := new(ssocookie.CookiePayload)

		// TODO: Pass sso_cookie as parameter to set U and G
		config.Authenticate = Authenticate
		sso_cookie_payload.U = config.Authenticate(r)

		expiration := time.Now().Add(config.Expiry)
		url_string := ssocookie.CreateCookie(ip, sso_cookie_payload,
			config.Privkey, config.Expiry)
		// TODO: Add domain / path / secure / HTTP Only
		cookie := http.Cookie{Name: "sso", Value: url_string,
			Expires: expiration, Secure: false, Domain: ".domain.dev"}
		http.SetCookie(w, &cookie)

		fmt.Fprintf(w, "You have been logged in!\n")
	})
} // ]]]

func RegisterHandlers(config *ssocookie.Config) { // [[[
	http.Handle("/login", LoginHandler(config))
} // ]]]

func ParseArgs(config *ssocookie.Config) { // [[[
	privatekeyfile := flag.String("privkey", "prime256v1-key.pem", "Filename of PEM-encoded ECC private key")

	flag.StringVar(&config.IPHeader, "real-ip", "X-Real-Ip", "Name of X-Real-IP Header")
	flag.IntVar(&config.Port, "port", 8080, "Listening port")
	flag.DurationVar(&config.Expiry, "expiry", 3600*time.Second, "Cookie expiry time (seconds)")
	flag.Parse()

	_, err := ssocookie.ReadECCPrivateKeyPem(*privatekeyfile, config)
	CheckError(err)
	log.Infof(">> Read ECC private key from %s", *privatekeyfile)
} // ]]]

func main() { // [[[
	config := new(ssocookie.Config)

	RegisterHandlers(config)

	ParseArgs(config)

	log.Infof(">> Server running on 127.0.0.1:%d", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", config.Port), nil))
} // ]]]

func CheckError(e error) { // [[[
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
} // ]]]
