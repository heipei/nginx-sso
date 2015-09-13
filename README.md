nginx-sso
=========

nginx-sso is a simple single-sign-on (SSO) solution to be used together with
nginx. It is based on ECC public key signatures and cookies.

Features
--------

With nginx-sso you can:

- Authenticate users
- Authorize users
- Provide user-information to your backend application

Building
--------

For now, use the Makefile by calling `make`.

Getting started
---------------

There is an example nginx.conf in doc/ 

1. Start nginx: ~/local/sbin/nginx -c $PWD/doc/nginx.conf
2. Start ssoauth: ./ssoauth -config config.json -pubkey run/prime256v1-public.pem -port 8082
3. Start ssologin: ./ssologin -privkey run/prime256v1-key.pem -port 8081
4. Add login.domain.dev and auth.domain.dev to 127.0.0.1 to /etc/hosts
5. Browse to login.domain.dev:8080/login
6. Browse to auth.domain.dev:8080/secret

ECC keypair generation
----------------------

To create an ECC keypair, you can use the tool in doc/ecc.go.
