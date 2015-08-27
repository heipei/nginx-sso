// vim:ft=go:foldmethod=marker:foldmarker=[[[,]]]

// ssoauth - Authenticate (verify) SSO cookie
//
// (c) 2015 by Johannes Gilger <heipei@hackvalue.de>
package main

// imports [[[
import (
	"crypto/ecdsa"
	"encoding/json"
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

func Unauthorized(w http.ResponseWriter) {
	http.Error(w, "Not logged in", http.StatusUnauthorized)
}

func AuthHandler(config *ssocookie.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// TODO: Debug
		for k, _ := range r.Header {
			log.Debugf("%s: %s", k, r.Header.Get(k))
		}

		// TODO: Verify these
		uri := r.Header.Get("X-Original-Uri")
		ip := r.Header.Get(config.IPHeader)
		host := r.Host

		if ip == "" {
			log.Warnf("Header %s missing", config.IPHeader)
			Unauthorized(w)
			return
		} else {
			log.Infof("Remote IP %s", ip)
		}

		// TODO: Also create function ParseCookie
		cookie_string, err := r.Cookie("sso")
		if err != nil {
			log.Infof("No sso cookie")
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}

		json_string, _ := url.QueryUnescape(cookie_string.Value)
		log.Infof("%s", json_string)
		sso_cookie := new(ssocookie.Cookie)

		err = json.Unmarshal([]byte(json_string), &sso_cookie)
		if err != nil {
			fmt.Println("Error unmarshaling JSON: ", err)
			http.Error(w, "Error", http.StatusUnauthorized)
			return
		}

		// Print remote address and UTC-adjusted timestamp in RFC3339
		// (profile of ISO 8601)
		log.Infof("New auth request from %s at %s ", ip,
			time.Now().UTC().Format(time.RFC3339))

		if ssocookie.VerifyCookie(ip, sso_cookie,
			config.Pubkey.(*ecdsa.PublicKey)) {

			w.Header().Set("Remote-User", sso_cookie.P.U)
			w.Header().Set("Remote-Groups", sso_cookie.P.G)
			w.Header().Set("Remote-Expiry", fmt.Sprintf("%d",
				sso_cookie.E))
		} else {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// TODO: Check that we have the headers
		acl, ok := config.Acl[host]

		if ok {
			log.Debugf("acl entry: %s", acl)

			log.Debugf("vhosts: %s", acl.UrlPrefixes)
			for prefix, rules := range acl.UrlPrefixes {
				fmt.Printf("%s: %s\n", prefix, rules)
				if strings.HasPrefix(uri, prefix) {
					log.Debugf("Found prefix %s for URL %s", prefix, uri)
					fmt.Println("Users: %s", rules.Users)
					// TODO: Move into functions, accept early
					for _, user := range rules.Users {
						if user == sso_cookie.P.U {
							fmt.Printf("Found user %s\n", user)
						}
					}
					for _, group := range rules.Groups {
						if strings.HasPrefix(sso_cookie.P.G, group) {
							fmt.Printf("Found group prefix %s\n", group)
						}
					}
				}
			}
		} else {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		log.Infof("Request for Host %s, Path %s", host, uri)
		fmt.Fprintf(w, "Authorized!\n")
		log.Infof("Login by %s", sso_cookie.P.U)
		return
	})

}

func CheckError(e error) { // [[[
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
} // ]]]

func ParseArgs(config *ssocookie.Config) { // [[[
	publickeyfile := flag.String("pubkey", "prime256v1-public.pem", "Filename of PEM-encoded ECC public key")
	configfile := flag.String("config", "config.json", "ACL config file (JSON)")

	flag.StringVar(&config.IPHeader, "real-ip", "X-Real-Ip", "Name of X-Real-IP Header")
	flag.IntVar(&config.Port, "port", 8080, "Listening port")
	flag.Parse()

	c, err := ioutil.ReadFile(*configfile)
	CheckError(err)
	fmt.Println("%s", string(c))

	err = json.Unmarshal(c, &config.Acl)
	CheckError(err)

	fmt.Println("%v", config.Acl)

	_, err = ssocookie.ReadECCPublicKeyPem(*publickeyfile, config)
	CheckError(err)
	log.Infof("Read ECC public key from %s", *publickeyfile)
} // ]]]

func main() { // [[[
	config := new(ssocookie.Config)

	http.Handle("/auth", AuthHandler(config))

	ParseArgs(config)

	log.SetLevel(log.DebugLevel)

	log.Infof("Server running on 127.0.0.1:%d", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", config.Port), nil))
} // ]]]
