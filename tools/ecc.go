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

// ECC keypair generator

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	//	dat, err := ioutil.ReadFile("prime256v1-key.pem")
	//	pemblock, _ := pem.Decode(dat)
	//	check(err)
	//	privkey, parseerr := x509.ParseECPrivateKey(pemblock.Bytes)
	//
	//	if parseerr != nil {
	//		fmt.Println(err)
	//	}
	//
	//	bytes, _ = x509.MarshalECPrivateKey(privkey)
	//	block = pem.Block{}
	//	block.Bytes = bytes
	//	block.Type = "EC PRIVATE KEY"
	//	bytes_encoded = pem.EncodeToMemory(&block)
	//	fmt.Println(string(bytes_encoded))
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
