nginx-sso
=========

nginx-sso is a simple single-sign-on (SSO) solution to be used together with
nginx and the nginx auth_request module. It uses ECC public key signatures and
cookies to work "offline" as far as the service provider is concerned.

With nginx-sso you can:

- Authenticate users
- Authorize users
- Provide user-information to your backend application

Overview
--------

nginx-sso consist of two components: The ssologin endpoint which will set the
sso cookie and the ssoauth endpoint which will consume the cookie.

The ssologin tool has to be customized to your own login architecture. It
requires customization to accomodate your user-credential store (be it LDAP,
htdigest, OAuth, homebrew). The common denominator is that it expects a
non-empty string for the username and an optional group-string
(comma-delimited). These two values will be encoded in the sso cookie.

The ssoauth tool takes the sso cookie, verifies its integrity (using the
attached signature) and finally checks the username and groups against a list
of ACL entries for different vhosts. If all of these checks pass, it will
return the username, groups and expiry time of the cookie to the nginx
frontend, which can pass it on to your application in the form of a plain HTTP
header. Your application could then use this header to find the user in its own
user database which could contain additional attributes (e.g. roles, contact
info, etc).

Building
--------

For now, use the Makefile by calling `make`. The ssologin.go is meant to be an
example on how to use the nginx-sso system to set the sso cookie during login.

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
