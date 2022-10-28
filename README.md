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

 
