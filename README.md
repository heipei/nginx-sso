nginx-sso - Simple offline SSO for nginx
========================================

nginx-sso is a simple single-sign-on (SSO) solution to be used with nginx and
the nginx auth_request module. It uses ECC public key signatures and cookies to
authenticate users in an *offline* fashion, as far as the service provider is
concerned.

With nginx-sso you can:

- Authenticate users and check session validty
- Authorize users to access specific resources
- Provide authenticated information about the user to your backend application
- Allow your application server to effectively stay offline

You can use it by deploying a single (static) binary and a config to a stock
nginx instance.

Overview
--------

nginx-sso works by creating a session cookie **sso**. This cookie contains
information about the user, the expiry date of his session and the IP of the
client which logged in.  Furthermore, the cookie contains an ECDSA signature
which protects the integrity of the payload during login. In our case, the
**ssologin** tool has the necessary ECC private key and creates the cookie and
the signature after a successful login.

The ssologin tool has to be customized to your own login architecture. It
requires customization to accomodate your user-credential store (be it LDAP,
htdigest, OAuth, homebrew). The common denominator is that it expects a
non-empty string for the username and an optional group-string
(comma-delimited). These two values will be encoded in the sso cookie.

Any service in the possession of the corresponding public key can then use the
information stored in the sso cookie. With nginx-sso, this is done by the
**ssoauth** tool. This tool is our *authentication endpoint* queried by nginx.
The ssoauth tool takes the sso cookie, verifies its integrity and freshness
(using the attached signature) and finally checks the username and groups
against a list of ACL entries for different vhosts. If all of these checks
pass, it will return the username, groups and expiry time of the cookie to the
nginx frontend, which can pass it on to your application in the form of a plain
HTTP header. Your application could then use this header to find the user in
its own user database which could contain additional attributes (e.g. roles,
contact info, etc).

More information can be found in the file [TECHNICAL.md](TECHNICAL.md).

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

Contributing
------------


nginx-sso is a work-in-progress and should not be used for production
applications. It is the first application I've developed in golang.  I'd like
to get some help to improve the codebase and make it more adaptable to other
setups. Please consider forking the repository and creating a pull-request on
Github.

Author
------

nginx-sso was written by Johannes Gilger. Any additional contributors will be
listed here.

License
-------

nginx-sso is licensed under the GNU General Public License v2. See the file
[LICENSE](LICENSE) for details.  
