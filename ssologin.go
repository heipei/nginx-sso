// ssologin - Login (create) SSO cookie
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
	"time"
)

type Config struct {
	Cookie  string
	Port    int
	Headers struct {
		Ip string
	}
	Privkeyfile string
	Privkey     *ecdsa.PrivateKey
	Expiration  int
	Expiry      time.Duration
	Domain      string
	Secure      bool
	Debug       bool
}

// TODO: Make this more general / better to integrate
func Authenticate(r *http.Request) (string, string) {
	return "jg123456", "x:engineering"
}

func LoginHandler(config *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip := r.Header.Get(config.Headers.Ip)
		if ip == "" {
			log.Warnf("Header %s missing", config.Headers.Ip)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}

		// Print remote address and UTC-adjusted timestamp in RFC3339
		// (profile of ISO 8601)
		log.Infof("New login request from %s at %s ", r.RemoteAddr,
			time.Now().UTC().Format(time.RFC3339))

		// Get the cookie payload from the Authenticate function
		sso_cookie_payload := new(ssocookie.CookiePayload)
		sso_cookie_payload.U, sso_cookie_payload.G = Authenticate(r)

		// Serialize the ssocookie into a string
		cookie_string := ssocookie.CreateCookie(ip, sso_cookie_payload,
			config.Privkey, config.Expiry)

		// Set the cookie
		expiration := time.Now().Add(config.Expiry)
		cookie := http.Cookie{Name: config.Cookie, Value: cookie_string,
			Expires: expiration, Secure: config.Secure, Domain: config.Domain}
		http.SetCookie(w, &cookie)

		fmt.Fprintf(w, "You have been logged in!\n")
	})
}

func RegisterHandlers(config *Config) {
	http.Handle("/login", LoginHandler(config))
}

func ParseArgs(config *Config) {
	configfile := flag.String("config", "etc/ssologin.json", "config file (JSON)")
	flag.BoolVar(&config.Debug, "debug", false, "Debug-level output")
	flag.Parse()

	// Read the config file
	c, err := ioutil.ReadFile(*configfile)
	CheckError(err)

	// Unmarshal the config file
	err = json.Unmarshal(c, &config)
	CheckError(err)

	// Convert Expiration (int) to time type
	config.Expiry = time.Duration(config.Expiration) * time.Second

	// Set appropriate log-level
	if config.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	privkey, err := ssocookie.ReadECCPrivateKeyPem(config.Privkeyfile)
	CheckError(err)
	config.Privkey = privkey
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
