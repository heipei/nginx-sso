/*
   nginx-sso - Simple cookie-based single-sign-on
   Copyright (C) 2015 by Johannes Gilger <heipei@hackvalue.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

// ssologin endpoint - Login (create) SSO cookie

package main

import (
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/heipei/nginx-sso/ssocookie"
	_ "github.com/mattn/go-sqlite3"
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

// Get a username and groups based on the HTTP request
// TODO: This is just an example
func Authenticate(r *http.Request) (string, string) {
	basic_user, basic_password, auth_ok := r.BasicAuth()

	if !auth_ok {
		log.Warnf("HTTP Basic Auth missing")
		return "", ""
	}

	db, err := sql.Open("sqlite3", "run/users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// FIXME: This is a table with plain user/pw. Probably not a good idea.
	sqlStmt := "create table users if not exists (username string not null primary key, password string not null, groups string default null);"
	_, err = db.Exec(sqlStmt)

	rows, err := db.Prepare("select username, password, groups from users where username = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var username string
	var password string
	var groups string

	err = rows.QueryRow(basic_user).Scan(&username, &password, &groups)
	if err != nil {
		log.Warnf("User %s not found in database: %s", basic_user, err)
		return "", ""
	}

	if basic_password == password {
		log.Debugf("User %s: Password matches!", basic_user)
		return username, groups
	} else {
		log.Warnf("User %s: Wrong password!", basic_user)
		return "", ""
	}
}

// Sets the details of the sso cookie
func SetSSOCookie(config *Config, w http.ResponseWriter, r *http.Request) bool {
	ip := r.Header.Get(config.Headers.Ip)
	if ip == "" {
		log.Warnf("Header %s missing", config.Headers.Ip)
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return false
	}

	// Print remote address and UTC-adjusted timestamp in RFC3339
	log.Infof("New login request from %s at %s ", ip, time.Now().UTC().Format(time.RFC3339))

	// Get the cookie payload from the Authenticate function
	sso_cookie_payload := new(ssocookie.CookiePayload)
	sso_cookie_payload.U, sso_cookie_payload.G = Authenticate(r)

	if sso_cookie_payload.U == "" {
		return false
	}

	// Serialize the ssocookie into a string
	cookie_string := ssocookie.CreateCookie(ip, sso_cookie_payload,
		config.Privkey, config.Expiry)

	// Set the cookie
	expiration := time.Now().Add(config.Expiry)
	cookie := http.Cookie{Name: config.Cookie, Value: cookie_string,
		Expires: expiration, Secure: config.Secure, Domain: config.Domain}
	http.SetCookie(w, &cookie)

	return true
}

func Unauthenticated(w http.ResponseWriter) {
	// Careful: StatusUnauthorized returns HTTP 401
	// HTTP 401 is called "Unauthorized", but actually means
	// "authentication failed" as per RFC 7235
	http.Error(w, "Not logged in", http.StatusUnauthorized)
}

func LoginHandler(config *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SetSSOCookie(config, w, r) {
			fmt.Fprintf(w, "You have been logged in!\n")
		} else {
			Unauthenticated(w)
		}
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
