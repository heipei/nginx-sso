// https://golang.org/src/crypto/x509/x509.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fmt.Println(key)
	fmt.Println(err)
	pubkey := key.Public()

	bytes, _ := x509.MarshalECPrivateKey(key)
	block := pem.Block{}
	block.Bytes = bytes
	block.Type = "EC PRIVATE KEY"
	bytes_encoded := pem.EncodeToMemory(&block)

	fmt.Println(string(bytes_encoded))
	if err != nil {
		fmt.Println(err)
	}

	bytes, _ = x509.MarshalPKIXPublicKey(pubkey)
	block = pem.Block{}
	block.Type = "EC PUBLIC KEY"

	block.Bytes = bytes
	bytes_encoded = pem.EncodeToMemory(&block)

	fmt.Println(string(bytes_encoded))
	if err != nil {
		fmt.Println(err)
	}

	dat, err := ioutil.ReadFile("prime256v1-key.pem")
	pemblock, _ := pem.Decode(dat)
	check(err)
	privkey, parseerr := x509.ParseECPrivateKey(pemblock.Bytes)

	if parseerr != nil {
		fmt.Println(err)
	}

	bytes, _ = x509.MarshalECPrivateKey(privkey)
	block = pem.Block{}
	block.Bytes = bytes
	block.Type = "EC PRIVATE KEY"
	bytes_encoded = pem.EncodeToMemory(&block)
	fmt.Println(string(bytes_encoded))
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
