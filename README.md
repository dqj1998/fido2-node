# fido2-node
A node.js FIDO2/WebAuthn server

# Status
It's still simple; it only supports FIDO2 registration and authentication now.

# Standard Features
## No requirement for browsers' features on the client side, like Cookies.

## Support real non-resident keys

# Extension Features 

## Multiple rp ids
The FIDO spec uses the RP server's domain name to identify RPs. We add an extension that one domain can support multiple RPs by set rp.id when calling attestation/options and assertion/options.

# Storage
Stoarge type is set by STORAGE_TYPE in .env

## mem
Memory stoarge. All data lost when restart. Good for test with clients

## mysql
Save data in a mysql database. REGISTERED_RPs of .env will be inserted into database if tehy aren't in datbase yet when start.
But never delete rps from database according to REGISTERED_RPs.

 
