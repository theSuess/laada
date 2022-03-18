Laada
===

_LDAP Azure Active Directory Authentication_

> :warning: This project is not yet feature complete! Please do not try to use
> it yet as things will most probably break.

Laada is a small service, allowing LDAP authentication with Azure Active
Directory as a backend. The primary use case is to allow authentication with
Azure AD for services which do not implement OIDC or SAML.

It accomplishes this by verifying the LDAP bind password with a registered TOTP
(either Hardware or software based).

After a user has registerd for the first time using the web interface, the
target flow looks like this:

1. Application asks user for credentials
2. User enters his email as username and TOTP token as password
3. The application sends this to the Laada LDAP endpoint
4. Laada verifies this bind with the TOTP backend
5. The bind succeeds or fails based on the response


Laada also exposes LDAP search capabilities, backed by the Microsoft Graph API


# FAQ

## Why not use Azure AD Domain Services?

Because it costs money and I don't want to spend it.

## Why use Azure AD at all?

Because I like its features (Self-Service, External user management, Advanced
access policies) and it is free in the basic variant.

## Why rust?

Because it was the first language with a usable LDAP server implementation that
I found and I wanted to learn it for a long time.
