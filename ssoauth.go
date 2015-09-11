// vim:ft=go:foldmethod=indent:foldnestmax=1

// ssoauth - Authenticate (verify) SSO cookie
//
// (c) 2015 by Johannes Gilger <heipei@hackvalue.de>
package main

// imports
import (
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/heipei/nginx-sso/ssocookie"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// structs
type AclConfig map[string]struct {
	Users       []string `json:"Users"`
	Groups      []string `json:"Groups"`
	UrlPrefixes map[string]struct {
		Users  []string `json:"Users"`
		Groups []string `Groups:"Groups"`
	} `json:"UrlPrefixes"`
}

type Config struct {
	Port    int
	Headers struct {
		Ip  string
		Uri string
	}
	Pubkeyfile string
	Pubkey     crypto.PublicKey
	Acl        AclConfig
	Debug      bool
}

func Unauthorized(w http.ResponseWriter) {
	http.Error(w, "Not logged in", http.StatusUnauthorized)
}

func GetHeaders(r *http.Request, config *Config) (string, string, string, error) {
	for k, _ := range r.Header {
		log.Debugf("%s: %s", k, r.Header.Get(k))
	}

	uri := r.Header.Get(config.Headers.Uri)
	ip := r.Header.Get(config.Headers.Ip)
	host := r.Host

	if ip == "" {
		log.Warnf("Header %s missing", config.Headers.Ip)
		return "", "", "", errors.New("Header missing")
	}

	if uri == "" {
		log.Warnf("Header %s missing", config.Headers.Uri)
		return "", "", "", errors.New("Header missing")
	}

	return uri, ip, host, nil
}

func VerifyAcl(r *http.Request, config *Config, host string, uri string, sso_cookie *ssocookie.Cookie) bool {
	acl, ok := config.Acl[host]

	if !ok {
		return false
	}

	log.Debugf("acl entry: %s", acl)

	log.Debugf("vhosts: %s", acl.UrlPrefixes)
	for prefix, rules := range acl.UrlPrefixes {
		if strings.HasPrefix(uri, prefix) {
			log.Debugf("%s%s: Users: %s, Groups: %s\n", host, prefix, rules.Users, rules.Groups)
			// TODO: Move into functions, accept early
			for _, user := range rules.Users {
				if user == sso_cookie.P.U {
					log.Debugf("Found user %s\n", user)
					return true
				}
			}
			for _, group := range rules.Groups {
				if strings.HasPrefix(sso_cookie.P.G, group) {
					log.Debugf("Found group prefix %s\n", group)
					return true
				}
			}
		}
	}
	return false
}

func CheckCookie(r *http.Request, config *Config, ip string, sso_cookie *ssocookie.Cookie) bool {
	cookie_string, err := r.Cookie("sso")
	if err != nil {
		log.Infof("No sso cookie from %s")
		return false
	}

	json_string, _ := url.QueryUnescape(cookie_string.Value)
	log.Debugf("JSON payload from %s: %s", ip, json_string)

	err = json.Unmarshal([]byte(json_string), &sso_cookie)
	if err != nil {
		log.Errorf("Error unmarshaling JSON: %s\n", err)
		return false
	}

	// Verify that the signature of the cookie is correct
	if !ssocookie.VerifyCookie(ip, sso_cookie,
		config.Pubkey.(*ecdsa.PublicKey)) {
		return false
	}

	return true
}

func AuthHandler(config *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Get the relevant headers
		uri, ip, host, err := GetHeaders(r, config)

		if err != nil {
			Unauthorized(w)
			return
		}

		// Print remote address and UTC-adjusted timestamp in RFC3339
		// RFC3339 is a profile of ISO 8601
		log.Infof("Request from %s for %s%s at %s", ip, host, uri, time.Now().UTC().Format(time.RFC3339))

		// Populate and check the SSO cookie
		sso_cookie := new(ssocookie.Cookie)
		cookie_ok := CheckCookie(r, config, ip, sso_cookie)

		if !cookie_ok {
			log.Warnf("Cookie for %s not OK", ip)
			Unauthorized(w)
			return
		}

		// Look for ACL entry for this host, URI, user and group
		acl_ok := VerifyAcl(r, config, host, uri, sso_cookie)

		if !acl_ok {
			log.Warnf("Found no ACL entry for %s%s for user %s, groups %s", host, uri, sso_cookie.P.U, sso_cookie.P.G)
			Unauthorized(w)
			return
		}

		// We arrived here, accept the request and set the reply headers
		w.Header().Set("Remote-User", sso_cookie.P.U)
		w.Header().Set("Remote-Groups", sso_cookie.P.G)
		w.Header().Set("Remote-Expiry", fmt.Sprintf("%d",
			sso_cookie.E))
		fmt.Fprintf(w, "Authorized!\n")

		log.Infof("Succesful request by %s for %s%s from %s", sso_cookie.P.U, host, uri, ip)
		return
	})
}

func CheckError(e error) {
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
}

func ParseArgs(config *Config) {
	debug := flag.Bool("debug", false, "Debug-level output")
	publickeyfile := flag.String("pubkey", "prime256v1-public.pem", "Filename of PEM-encoded ECC public key")
	configfile := flag.String("config", "config.json", "ACL config file (JSON)")

	flag.StringVar(&config.Headers.Ip, "real-ip", "X-Real-Ip", "Name of X-Real-IP Header")
	flag.IntVar(&config.Port, "port", 8080, "Listening port")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	c, err := ioutil.ReadFile(*configfile)
	CheckError(err)

	err = json.Unmarshal(c, &config)
	CheckError(err)

	log.Debugf("%v", config)

	config.Pubkey, err = ssocookie.ReadECCPublicKeyPem(*publickeyfile, config.Pubkey)
	CheckError(err)
	log.Infof("Read ECC public key from %s", *publickeyfile)
}

func main() {
	log.Infof("ssoauth starting")
	config := new(Config)

	http.Handle("/auth", AuthHandler(config))

	ParseArgs(config)

	log.Infof("ssoauth server running on 127.0.0.1:%d", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", config.Port), nil))
}
