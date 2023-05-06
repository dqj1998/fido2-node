# fido2-node
A node.js FIDO2/WebAuthn server passed FIDO Conformance Tool 1.7.11

https://user-images.githubusercontent.com/4339123/230692122-d19b6154-d094-46d6-b6b7-31aabaeb9cce.mp4


# Status
Supports full FIDO2 server spec with extra extensions.

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
The limitation of browsers is that the domain set must be a domain suffix of the current domain or equal to the current domain.
dFido2Lib-android and dFido2Lib-ios SDKs are not this limilation.

## Unique device binded key
Cannot auth with a unique device binded key from a different device(another installation of SDK).
Open/close this feature by the boolean config of device_bind_key in domain.json. The default is false.
Usually, this feature is to force disable key synchronization among devices to gain a more robust security level.
dFido2Lib-ios and dFido2Lib-android SDKs support this feature.

# User device APIs

## List user's devices
/usr/dvc/lst

Parameters required in JSON of HTTP request body: 

session: Session ID created by FIDO2 registration or authentication API. Finding user by this session ID.

rpID: (optional)Client domain will be used if not set

Return in JSON:

session: Session ID the same as request

status:  always ok

devices: The list of the user's devices

There are JSOn fields below in one element of device list:

device_id: The ID of device

userAgent: Browser user agent information

desc: The description of this aaguid in MDS3 if it's a reistered aaguid

registered_time: The time of the device registered

## Remove an user device
/usr/dvc/rm

Parameters required in JSON of HTTP request body: 

session: Session ID created by FIDO2 registration or authentication API. Finding user by this session ID.

rpID: (optional)Client domain will be used if not set

device_id: The dvice ID to remove

Return in JSON:

session: Session ID the same as request

status:  ok or fail

remain_count: How may devices remain in this user's list after removing

# User session API
/usr/validsession

Validating if a session ID is alive. Client web site can use this to manage user session.

Parameters required in JSON of HTTP request body: 

session: Session ID created by FIDO2 registration or authentication API. Finding user by this session ID.

rpID: (optional)Client domain will be used if not set

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

# FIDO Conformance test
We passed the latest version of FIDO Conformance Tools with MDS3

## Preperations
1. Download Metadata by clicking DOWNLOAD TEST METADATA on FIDO conformance tools
2. Copy all files into fido-conformance-metadata-statements
3. Set FIDO_CONFORMANCE_TEST=1 in .env file
4. Restart fido2-node

# Troubleshoot
## AxiosError at booting when opened FIDO_CONFORMANCE_TEST=1
This is caused by expired MDS3 BLOB download url in config-fido-conformance.json