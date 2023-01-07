# fido2-node
A node.js FIDO2/WebAuthn server

# Status
It's still simple; it only supports FIDO2 registration and authentication now.

# Standard Features
## No requirement for browsers' features on the client side, like Cookies.

## Support real non-resident keys

## Enterprise authenticator
Support aaguid checking for enterprise attestation.
1. Register enterpise rpids and aaguids in env file of server by ENTERPRISE_RPs and ENTERPRISE_AAGUIDs
2. Call setPlatformAuthenticatorAAGUID and addEnterpriseRPIds on SDK side

# Extension Features

## Multiple rp ids
The FIDO spec uses the RP server's domain name to identify RPs. We add an extension that one domain can support multiple RPs by set rp.id when calling attestation/options and assertion/options.

# Storage
Stoarge type is set by STORAGE_TYPE in .env

## mem
Memory stoarge. All data lost when restart. Good for test with clients

## mysql
Save data in a mysql database. REGISTERED_RPs of .env will be inserted into database if they aren't in database yet when start.
But never delete rps from database according to REGISTERED_RPs.

* The aaguids of ENTERPRISE_AAGUIDs can be Array so that we can support the seamless upgrade of aaguids.

 
