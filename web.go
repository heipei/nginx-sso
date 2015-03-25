package main

import (
	"crypto/ecdsa"
	//	"crypto/elliptic"
	//	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
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

func login_handler(w http.ResponseWriter, r *http.Request) {
	// This is how you get request headers
	if val, ok := r.Header["User-Agent"]; ok {
		fmt.Printf("%s\n", val[0])
	}

	// Get the remote address
	fmt.Printf(">> New login request from %s\n", r.RemoteAddr)

	// Iterate over all headers
	// Join strings
	for key, value := range r.Header {
		fmt.Printf("%s: %s\n", key, strings.Join(value, ""))
	}

	// This is how you set response headers
	w.Header().Set("Custom-Header", "Jojo")

	// This is how you set the status code and return immediately
	// w.WriteHeader(404)

	fmt.Fprintf(w, "%#v\n", config.pubkey)
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

	_, err := readEcPrivateKeyPem("prime256v1-key.pem")
	check(err)

	_, err = readEcPublicKeyPem("prime256v1-public.pem")
	check(err)

	fmt.Printf("Server running\n")
	http.ListenAndServe(":8080", nil)
}
