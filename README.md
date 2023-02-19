# fido2-node
A node.js FIDO2/WebAuthn server

# Status
Supports FIDO2 registration/authentication and some extensions.

# Standard Features
## No requirement for browsers' features on the client side, like Cookies.

## Support real non-resident keys

## Enterprise authenticator
Support aaguid checking for enterprise attestation.
1. Register enterpise rpids and aaguids by domain.json file
2. Call setPlatformAuthenticatorAAGUID and addEnterpriseRPIds on SDK side

* The enterprise_aaguids of domain.json is Array so that we can support the seamless upgrade of aaguids.

# Extension Features

## Multiple rp ids
The FIDO spec uses the RP server's domain name to identify RPs. We add an extension that one domain can support multiple RPs by set rp.id when calling attestation/options and assertion/options.

## Unique device binded key
Cannot auth with a unique device binded key from a different device(another installation of SDK).
Open/close this feature by the boolean config of device_bind_key in domain.json. The default is false.
Usually, this feature is to force disable key synchronization among devices to gain a more robust security level.

# Storage
Stoarge type is set by STORAGE_TYPE in .env

## mem
Memory stoarge. All data lost when restart. Good for test with clients

## mysql
Save data in a mysql database.

# Management methods

## .env config file
There are basic configurations, loaded when server start

## domain.json
Domain settings, loaded when server start, and can be changed and reloaded by HTTPS APIs

## HTTPS APIs

[POST /mng/domain/conf] set and/or delete domain configs

Body is JSON with MNG_TOKEN. Refer the set_domain.json in examples folder

[POST /mng/domain/rollback] rollback domain config to pervious one

Body is JSON with MNG_TOKEN:

{
    "MNG_TOKEN":"<The token set in server .env file>"
}

* For security, you can deny external access to /mng on your firewall.