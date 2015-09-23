nginx-sso - Design document
===========================

This document details the technical architecture and reasoning behind the
nginx-sso system.

The request flow
----------------
    +--------------+  User / Pass
    | (nginx)      |  <----------+
    | ssologin     |   SSO Cookie    User
    | ECC PrivKey  |  +---------->
    +--------------+    Step 1+2     +
    login.domain.dev                 | SSO Cookie
                                     | Step 3
      Step 9      Step 8             v           Step 4+7    Step 5+6 
    +---------+ <-----------  +---------------+ ---------> +------------+
    | Service |  Remote-User  |  nginx        |  Cookie    | ssoauth    |
    +---------+  Remote-Group |  auth_request | <--------- | ECC PubKey |
                              +---------------+  Username  | ACL        |
                               auth.domain.dev   Groups    +------------+
                                                                    

1. The user performs a login at the **ssologin** tool resource on
   `login.domain.dev`.
2. The **ssologin** returns the encoded **sso** cookie to the user.
3. The user makes a request for a protected resource on `auth.domain.dev`.
4. nginx performs a subrequest to the **ssoauth** backend, containing the
   headers of the original request.
5. The **ssoauth** backend decodes and verifies the cookie.
6. The **ssoauth** backend queries its ACL about whether the user can access
   this specific resource.
7. On success, the **ssoauth** backend sets the response headers in response to
   the subrequest.
8. nginx takes the response headers of the subrequest and forwards them to the
   **service** application.
9. The **service** application can use the Remote-User / Remote-Group header
   as-is.

The sso cookie
--------------

nginx-sso is a single-sign-on system for HTTP which is based on cookies and
ECDSA signatures. The centerpiece of nginx-sso is the 'sso' cookie which looks
like this:

`sso: { Payload: { username, groups}, Expiry, R, S (ECDSA sig) }`

or to put it in types:

`sso: { P: { U: string, G: string }, E: int, R: bignum, S: bignum }`

The cookie contains some payload (in our case a username and a groups string),
an expiry and an ECDSA signature over the payload, the expiry and the IP of
client. The receiver can thereby verify that the content of the payload has not
been modified, that the cookie has not expired and that the IP of the client
didn't change.

The cookie payload is serialized into JSON and URL-escaped to be stored as an
actual cookie. It is created by the **ssologin** tool once a user has successfully
identified himself and will be set for a common domain.

Only the ssologin tool will need to be in possession of the corresponding ECC
private key. This way, even if an application server is compromised, it can not
be used to issue false sso cookies.

The nginx auth request endpoint
-------------------------------

nginx has a number of builtin authentication modules. The auth_request module
makes the decision of allowing a request for resource by issuing its own
subrequest to a specified resource ("auth endpoint"). The auth endpoint can
either reply with a HTTP 200 (OK) or it can issue a HTTP 401/403
(Unauthenticated / Unauthorized).

Our endpoint is called **ssoauth**, and for performance-reasons it should run
on the same hosts as the nginx instance. To make the decision (accept/deny),
the auth endpoint can retrieve the details of the original request to nginx
from different (custom) headers: `X-Original-Uri` (the URI which was
requested), `X-Real-Ip` (the original IP) plus any headers that were part of
the original request (including the **sso** cookie). The auth_request module
does not need to forward the body of the original request, only its headers.

When the auth endpoint replies to nginx, it can do so with its own headers.
These can be copied and then passed on to whatever proxied backend is protected
by the auth_request module in the first place. In our case, the ssoauth backend
will reply with the headers `Remote-User`, `Remote-Groups` and `Remote-Expiry` if
authentication was successful.

Authentication for backend applications
---------------------------------------

ssoauth offers authentication by verifying the sso cookie with a supplied ECC
public key and, if successful, returning the username, groups and expiry time
to the nginx server. If these headers are copied and passed on to a backend
(via the proxy statement), the backend can thus make use of these headers to
identify the user. Authentication logic becomes much easier this way since your
application no longer needs to deal with sessions, expiry, passwords, groups,
etc. All it needs is a mapping of username (or group affiliations) to
permissions.

Authorization
-------------

ssoauth also implements mandatory authorization logic in the form of an ACL.
This ACL is a structure which contains a list of permitted users and groups for
each vhost and any number of URI prefixes for these vhosts. This way, you can
even protect "dumb" resources (static websites etc) with nginx-sso. If a vhost
has a URI prefix section, the usernames / groups in this section will override
the global vhost configuration for this prefix.

Benefits
--------

- golang, simple deploys (one static binary, config and pubkey for services)
- Few "moving parts" (e.g. no interconnectivity between services and IdP)
- Works with stock nginx (no out-of-tree patches or lua modules)
- Safe default (ssoauth breaks -> authentication fails)
- The simplest way to provide SSO to different applications (via HTTP headers)

Limitations
-----------

- Revocation of an active session is not possible unless you were to blacklist
  the user at each service.
- Inclusion of additional user attributes will result in the cookie growing.
- nginx-sso will only work across the same domain due to the cookie.
- Performance might be a concern.
- Setup might seem complex, but is relatively straightforward compared to similar systems.

Similar software
----------------
- [https://neon1.net/mod_auth_pubtkt/](https://neon1.net/mod_auth_pubtkt/) - Apache-only, almost works like nginx-sso
- [http://www.openfusion.com.au/labs/mod_auth_tkt/](http://www.openfusion.com.au/labs/mod_auth_tkt/) - Apache mod_auth_tkt
- [Pubcookie](http://pubcookie.org/) - Apache-only, Pubcookie system 

Resources
---------
- nginx documentation: http://nginx.org/en/docs/http/ngx_http_auth_request_module.html
- old pubcookie implemenation for nginx: http://www.vanko.me/book/page/pubcookie-module-nginx
