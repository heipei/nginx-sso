nginx-sso
=========

nginx-sso is a simple single-sign-on (SSO) solution to be used together with
nginx and the nginx auth_request module. It uses ECC public key signatures and
cookies to work "offline" as far as the service provider is concerned.

With nginx-sso you can:

- Authenticate users
- Authorize users to access a specific resource
- Provide authenticated user-information to your backend application
- Allow your application server to effectively stay offline

All by deploying a single (static) binary + config to a stock nginx instance.

nginx-sso is still very much work-in-progress and should not be used for
production applications. It is the first application I've developed using
golang and probably shows as much in various places.

Overview
--------

nginx-sso works by creating a session cookie called 'sso'. This cookie contains
information about the user, the expiry date and the IP of the client.
Furthermore, the cookie is protected by an ECDSA signature across the payload
during login. In our case, the 'ssologin' tool will create that cookie.

Any service in the possession of the corresponding public key can therefore
extract the information from the cookie and verify that it is intact and still
valid. This is done by the 'ssoauth' tool.

The ssologin tool has to be customized to your own login architecture. It
requires customization to accomodate your user-credential store (be it LDAP,
htdigest, OAuth, homebrew). The common denominator is that it expects a
non-empty string for the username and an optional group-string
(comma-delimited). These two values will be encoded in the sso cookie.

The ssoauth tool takes the sso cookie, verifies its integrity and freshness
(using the attached signature) and finally checks the username and groups
against a list of ACL entries for different vhosts. If all of these checks
pass, it will return the username, groups and expiry time of the cookie to the
nginx frontend, which can pass it on to your application in the form of a plain
HTTP header. Your application could then use this header to find the user in
its own user database which could contain additional attributes (e.g. roles,
contact info, etc).

More information can be found in the file TECHNICAL.md.

Building
--------

For now, use the Makefile by calling `make`. The ssologin.go is meant to be an
example on how to use the nginx-sso system to set the sso cookie during login.

Getting started
---------------

There is an example nginx.conf in etc/ 

1. Start nginx: ~/local/sbin/nginx -c $PWD/etc/nginx.conf
2. Generate a keypair using the ecc.go tool in tools/
3. Start ssoauth: ./ssoauth -config etc/ssoauth.json
4. Start ssologin: ./ssologin -config etc/ssologin.json
5. Add login.domain.dev and auth.domain.dev to 127.0.0.1 to /etc/hosts
6. Browse to http://username:password@login.domain.dev:8080/login
7. Browse to http://auth.domain.dev:8080/secret

Author
------

nginx-sso was conceived by Johannes Gilger. Any additional contributors will be
listed here.

License
-------

nginx-sso is licensed under the GNU General Public License v2. See the file
`LICENSE` for details.  
