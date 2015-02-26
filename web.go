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
)

func readEcPublicKeyPem(filename string) (interface{}, error) {
	dat, err := ioutil.ReadFile(filename)
	check(err)

	pemblock, _ := pem.Decode(dat)

	pubkey, err := x509.ParsePKIXPublicKey(pemblock.Bytes)
	check(err)

	fmt.Println(pubkey)

	return pubkey, err
}

func readEcPrivateKeyPem(filename string) (*ecdsa.PrivateKey, error) {
	dat, err := ioutil.ReadFile(filename)
	check(err)

	pemblock, _ := pem.Decode(dat)

	privkey, err := x509.ParseECPrivateKey(pemblock.Bytes)
	check(err)

	bytes, err := x509.MarshalECPrivateKey(privkey)
	check(err)

	block := pem.Block{}
	block.Bytes = bytes
	block.Type = "EC PRIVATE KEY"
	bytes_encoded := pem.EncodeToMemory(&block)
	fmt.Println(string(bytes_encoded))

	pubkey := privkey.Public()

	bytes, _ = x509.MarshalPKIXPublicKey(pubkey)
	block = pem.Block{}
	block.Type = "EC PUBLIC KEY"

	block.Bytes = bytes
	bytes_encoded = pem.EncodeToMemory(&block)

	fmt.Println(string(bytes_encoded))

	return privkey, err
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	http.HandleFunc("/", handler)
	_, err := readEcPrivateKeyPem("prime256v1-key.pem")
	check(err)

	_, err = readEcPublicKeyPem("prime256v1-public.pem")
	check(err)

	fmt.Printf("Server running\n")
	http.ListenAndServe(":8080", nil)
}
