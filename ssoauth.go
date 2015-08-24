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
	"time"
) // ]]]

func AuthHandler(config *ssocookie.Config) http.Handler { // [[[
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
		sso_cookie := new(ssocookie.Cookie)

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
			config.Pubkey.(*ecdsa.PublicKey)) {

			w.Header().Set("Remote-User", sso_cookie.P.U)
			w.Header().Set("Remote-Groups", sso_cookie.P.G)
			w.Header().Set("Remote-Expiry", fmt.Sprintf("%d",
				sso_cookie.E))
		} else {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		/*
			for k, v := range r.Header {
				log.Infof("%s:%s", k, v)
			}
		*/

		log.Infof(">> Request for Host %s, Path %s", r.Host, r.URL.Path)
		fmt.Fprintf(w, "Authorized!\n")
		log.Infof(">> Login by %s", sso_cookie.P.U)
		return
	})

} // ]]]

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

	err = json.Unmarshal(c, &config.Acl)
	CheckError(err)

	_, err = ssocookie.ReadECCPublicKeyPem(*publickeyfile, config)
	CheckError(err)
	log.Infof(">> Read ECC public key from %s", *publickeyfile)
} // ]]]

func main() { // [[[
	config := new(ssocookie.Config)

	http.Handle("/auth", AuthHandler(config))

	ParseArgs(config)

	log.Infof(">> Server running on 127.0.0.1:%d", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", config.Port), nil))
} // ]]]
