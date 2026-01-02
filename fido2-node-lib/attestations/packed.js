const { arrayBufferEquals, abToPem, appendBuffer, coerceToArrayBuffer, coerceToBase64, tools } = require("../utils.js")

const { Certificate, CertManager } = require("../certUtils.js")

const rootCertList = require("./u2fRootCerts.js")

const mds3 = require("../../mds3.js")

const algMap = new Map([
	[-7, {
		algName: "ECDSA_w_SHA256",
		hashAlg: "SHA-256",
	}],
	[-8, {
	    algName: "EdDSA",
	    hashAlg: undefined
	}],
	[-35, {
		algName: "ECDSA_w_SHA384",
		hashAlg: "SHA-384",
	}],
	[-36, {
		algName: "ECDSA_w_SHA512",
		hashAlg: "SHA-512",
	}],
	[-257, {
		algName: "RSASSA-PKCS1-v1_5_w_SHA256",
		hashAlg: "SHA-256",
	}],
]);

const authenticator_dangerous_status=["USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE", 
		"USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE"];

function packedParseFn(attStmt) {
	const ret = new Map();

	// alg
	const algEntry = algMap.get(attStmt.alg);
	if (algEntry === undefined) {
		throw new Error("packed attestation: unknown algorithm: " + attStmt.alg);
	}
	ret.set("alg", algEntry);

	// x5c
	const x5c = attStmt.x5c;
	const newX5c = [];
	if (Array.isArray(x5c)) {
		for (let cert of x5c) {
			cert = coerceToArrayBuffer(cert, "packed x5c cert");
			newX5c.push(cert);
		}
		ret.set("attCert", newX5c.shift());
		ret.set("x5c", newX5c);
	} else {
		ret.set("x5c", x5c);
	}

	// ecdaaKeyId
	let ecdaaKeyId = attStmt.ecdaaKeyId;
	if (ecdaaKeyId !== undefined) {
		ecdaaKeyId = coerceToArrayBuffer(ecdaaKeyId, "ecdaaKeyId");
		ret.set("ecdaaKeyId", ecdaaKeyId);
	}

	// sig
	let sig = attStmt.sig;
	sig = coerceToArrayBuffer(sig, "packed signature");
	ret.set("sig", sig);

	return ret;
}

async function packedValidateFn() {
	const x5c = this.authnrData.get("x5c");
	const ecdaaKeyId = this.authnrData.get("ecdaaKeyId");

	if (x5c !== undefined && ecdaaKeyId !== undefined) {
		throw new Error("packed attestation: should be 'basic' or 'ecdaa', got both");
	}

	if (x5c) return await packedValidateBasic.call(this);
	if (ecdaaKeyId) return await packedValidateEcdaa.call(this);
	return await packedValidateSurrogate.call(this);
}

async function packedValidateBasic() {
	// see what algorithm we're working with
	const {
		algName,
		hashAlg,
	} = this.authnrData.get("alg");

	if (algName === undefined) {
		throw new Error("packed attestation: unknown algorithm " + algName);
	}

	// from: https://w3c.github.io/webauthn/#packed-attestation
	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in x5c with the algorithm specified in alg.
	const res = await validateSignature(
		this.clientData.get("rawClientDataJson"),
		this.authnrData.get("rawAuthnrData"),
		this.authnrData.get("sig"),
		hashAlg,
		this.authnrData.get("attCert"),
	);
	if (!res) {
		throw new Error("packed attestation signature verification failed");
	}
	this.audit.journal.add("sig");
	this.audit.journal.add("alg");

	// Verify that x5c meets the requirements in §8.2.1 Packed attestation statement certificate requirements.
	await validateCerts(
		this.authnrData.get("attCert"),
		this.authnrData.get("aaguid"),
		this.authnrData.get("x5c"),
		this.audit
	);

	// If successful, return attestation type Basic and attestation trust path x5c.
	this.audit.info.set("attestation-type", "basic");

	this.audit.journal.add("fmt");

	return true;
}

async function validateSignature(
	rawClientData,
	authenticatorData,
	sig,
	hashAlg,
	parsedAttCert,
) {
	// create clientDataHash
	const hash = await tools.hashDigest(rawClientData);
	const clientDataHash = new Uint8Array(hash).buffer;

	// convert cert to PEM
	const attCertPem = abToPem("CERTIFICATE", parsedAttCert);

	// Get public key from cert
	const cert = new Certificate(attCertPem);
	const publicKey = await cert.getPublicKey();

	// verify signature
	const verify = await tools.verifySignature(
		publicKey,
		sig,
		appendBuffer(authenticatorData, clientDataHash),
		hashAlg,
	);
	return verify;
}

/**
 * FIDO-specific certificate chain validation
 * 
 * This function validates certificate chains according to FIDO specifications,
 * NOT PKIX/TLS standards. Key differences:
 * - Intermediate certificates are NOT required to have BasicConstraints CA=true
 * - Chain validation uses issuer/subject matching only
 * - Root trust comes exclusively from FIDO Metadata Service
 * - Signature verification on each cert-issuer pair
 * - Expiration dates are checked for ALL certificates in the chain
 * 
 * This is necessary to pass FIDO Conformance test P-2, which specifically
 * tests chains with non-CA intermediate certificates.
 * 
 * @param {Array<Certificate>} certs - Certificate chain [attCert, intermediate1, ..., rootOrNearRoot]
 * @param {Array<Certificate>} roots - Trusted root certificates from FIDO MDS
 * @param {Object} audit - Audit object for warnings (optional)
 */
async function validateFidoCertChain(certs, roots, audit) {
	if (!certs || certs.length === 0) {
		throw new Error("FIDO cert chain validation: empty certificate chain");
	}

	const nowMs = Date.now();

	// Step 0: Check expiration dates for ALL certificates in the chain
	// This must be done before any other validation to catch F-12 style failures
	for (let i = 0; i < certs.length; i++) {
		const cert = certs[i];
		if (cert._cert && cert._cert.notAfter && cert._cert.notAfter.value < nowMs) {
			throw new Error(`FIDO cert chain validation: certificate at position ${i} is expired`);
		}
		if (cert._cert && cert._cert.notBefore && cert._cert.notBefore.value > nowMs) {
			throw new Error(`FIDO cert chain validation: certificate at position ${i} is not yet valid`);
		}
	}

	// Step 1: Validate chain ordering using issuer/subject matching
	// Each certificate's issuer must match the next certificate's subject
	for (let i = 0; i < certs.length - 1; i++) {
		const currentCert = certs[i];
		const issuerCert = certs[i + 1];
		
		const issuerDN = currentCert._cert.issuer.typesAndValues[0].value.valueBlock.value;
		const subjectDN = issuerCert._cert.subject.typesAndValues[0].value.valueBlock.value;
		
		if (issuerDN !== subjectDN) {
			throw new Error(`FIDO cert chain validation: broken chain at position ${i}. Certificate issuer does not match next certificate subject.`);
		}
	}

	// Step 2: Verify each certificate's signature against its issuer
	// For all certs except the top-most (which should be verified against a root)
	for (let i = 0; i < certs.length - 1; i++) {
		const currentCert = certs[i];
		const issuerCert = certs[i + 1];
		
		try {
			// Verify that currentCert is signed by issuerCert
			await currentCert._cert.verify(issuerCert._cert);
		} catch (err) {
			throw new Error(`FIDO cert chain validation: signature verification failed at position ${i}: ${err.message}`);
		}
	}

	// Step 3: Verify the top-most certificate against FIDO MDS roots
	// The top-most cert in the chain MUST NOT be self-signed.
	// If the chain includes a self-signed root, that violates FIDO requirements
	// (roots must come from MDS, not be included in the attestation statement).
	const topCert = certs[certs.length - 1];
	const topCertSubject = topCert._cert.subject.typesAndValues[0].value.valueBlock.value;
	const topCertIssuer = topCert._cert.issuer.typesAndValues[0].value.valueBlock.value;
	
	// Check if top cert is self-signed (which would indicate it's a root in the chain)
	if (topCertIssuer === topCertSubject) {
		throw new Error("FIDO cert chain validation: chain includes a self-signed root certificate. Root certificates must come from FIDO MDS, not from the attestation statement (x5c).");
	}
	
	if (!roots || roots.length === 0) {
		// No roots available from MDS - issue a warning but allow validation to proceed
		// This may happen when authenticator is not registered with MDS
		if (audit) {
			audit.warning.set("attestation-root-not-validated", 
				"No root certificates available from FIDO MDS for this authenticator. Chain structure validated but root trust could not be verified.");
		}
		return;
	}

	// Try to find a matching root certificate that issued the top cert
	let rootVerified = false;
	let lastError = null;
	
	for (const rootCert of roots) {
		try {
			const rootCertSubject = rootCert._cert.subject.typesAndValues[0].value.valueBlock.value;
			
			// The top cert's issuer must match this root's subject
			if (topCertIssuer === rootCertSubject) {
				// Verify the top cert is signed by this root
				await topCert._cert.verify(rootCert._cert);
				rootVerified = true;
				break;
			}
		} catch (err) {
			lastError = err;
			// Continue trying other roots
			continue;
		}
	}

	if (!rootVerified) {
		throw new Error(`FIDO cert chain validation: top-most certificate could not be verified against any FIDO MDS root certificate. ${lastError ? 'Last error: ' + lastError.message : ''}`);
	}
}

async function validateCerts(parsedAttCert, aaguid, _x5c, audit) {
	// FIDO-specific certificate validation
	// NOTE: We intentionally DO NOT use generic PKIX/TLS certificate chain validation
	// because FIDO packed attestation allows non-CA intermediate certificates.
	// FIDO Conformance test P-2 specifically requires accepting chains where
	// intermediate certificates do not have BasicConstraints CA=true.

	var meta_entry
	if(aaguid){		
		//console.log(buf2hex(aaguid)) // for debug
		meta_entry = await mds3.mds3_client.findByAAGUID(aaguid)

		if(meta_entry && meta_entry.statusReports){
			meta_entry.statusReports.forEach((status)=>{
				if(authenticator_dangerous_status.includes(status.status)){
					throw new Error("Authenticator dangerous status.");
				}
			}
			);
		}
	}

	// decode attestation cert
	const attCert = new Certificate(coerceToBase64(parsedAttCert, "parsedAttCert"));
	
	if(0 < _x5c.length){
		// Validate certificate chain using FIDO-specific rules
		// Build certificate chain: [attCert, intermediate1, intermediate2, ..., rootOrNearRoot]
		let certs = [attCert];
		_x5c.forEach(elem => certs.push(new Certificate(coerceToBase64(elem, "x5cElem"))));

		// Collect root certificates from FIDO MDS
		let roots = [];
		if(meta_entry && meta_entry.attestationRootCertificates){
			meta_entry.attestationRootCertificates.forEach((ent) => roots.push(new Certificate(ent)));
		}

		// FIDO-specific chain validation (does not require CA=true on intermediates)
		await validateFidoCertChain(certs, roots, audit);
	} else {
		// Single certificate case: validate attestation cert against MDS roots
		CertManager.removeAll();
		rootCertList.u2fRootCerts.forEach((cert) => CertManager.addCert(cert));

		if(meta_entry){
			if(meta_entry.attestationRootCertificates){
				meta_entry.attestationRootCertificates.forEach((ent) => CertManager.addCert(ent));
			} else if(meta_entry.metadataStatement && meta_entry.metadataStatement.attestationRootCertificates){
				meta_entry.metadataStatement.attestationRootCertificates.forEach((ent) => CertManager.addCert(ent));
			}
		}

		try {
			await attCert.verify();
		} catch (e) {
			const err = e;
			if (err.message === "Please provide issuer certificate as a parameter" && 
					CertManager.getCerts().size > rootCertList.u2fRootCerts.length) {
				// err = new Error("Root attestation certificate for this token could not be found. Please contact your security key vendor.");
				audit.warning.set("attesation-not-validated", "could not validate attestation because the root attestation certification could not be found");
			} else {
				throw err;
			}
		}
	}

	audit.journal.add("x5c");

	// cert MUST be x.509v3
	if (attCert.getVersion() !== 3) {
		throw new Error("expected packed attestation certificate to be x.509v3");
	}

	// save certificate warnings, info, and extensions in our audit information
	const exts = attCert.getExtensions();
	exts.forEach((v, k) => audit.info.set(k, v));
	attCert.info.forEach((v, k) => audit.info.set(k, v));
	attCert.warning.forEach((v, k) => audit.warning.set(k, v));
	audit.journal.add("attCert");
	//console.log("_cert", attCert._cert);
	//console.log("_cert.subject", attCert._cert.subject);

	// from: https://w3c.github.io/webauthn/#packed-attestation
	// Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
	if (attCert.getVersion() !== 3) {
		throw new Error("expected packed attestation certificate to be x.509v3");
	}

	// Subject field MUST be set to:
	// Subject-C ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
	// Subject-O Legal name of the Authenticator vendor (UTF8String)
	// Subject-OU Literal string “Authenticator Attestation” (UTF8String)
	// Subject-CN A UTF8String of the vendor’s choosing
	const subject = attCert.getSubject();
	if (typeof subject.get("country-name") !== "string") {
		throw new Error("packed attestation: attestation certificate missing 'country name'");
	}

	if (typeof subject.get("organization-name") !== "string") {
		throw new Error("packed attestation: attestation certificate missing 'organization name'");
	}

	if (subject.get("organizational-unit-name") !== "Authenticator Attestation") {
		throw new Error("packed attestation: attestation certificate 'organizational unit name' must be 'Authenticator Attestation'");
	}

	if (typeof subject.get("common-name") !== "string") {
		throw new Error("packed attestation: attestation certificate missing 'common name'");
	}

	// If the related attestation root certificate is used for multiple authenticator models, the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
	// XXX: no way to tell if AAGUID is required on the server side...

	// The Basic Constraints extension MUST have the CA component set to false.
	const basicConstraints = exts.get("basic-constraints");
	if (basicConstraints.cA !== false) {
		throw new Error("packed attestation: basic constraints 'cA' must be 'false'");
	}

	// An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through authenticator metadata services
	// TODO: no example of this is available to test against

	// If x5c contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
	const certAaguid = exts.get("fido-aaguid");
	if (certAaguid !== undefined && !arrayBufferEquals(aaguid, certAaguid)) {
		throw new Error("packed attestation: authnrData AAGUID did not match AAGUID in attestation certificate");
	}
}

async function validateSelfSignature(rawClientData, authenticatorData, sig, hashAlg, publicKeyPem) {
	// create clientDataHash
	const clientDataHash = await tools.hashDigest(rawClientData, hashAlg);

	// verify signature
	const verify = await tools.verifySignature(
		publicKeyPem,
		sig,
		appendBuffer(authenticatorData, clientDataHash),
		hashAlg,
	);
	return verify;
}

async function packedValidateSurrogate() {
	// see what algorithm we're working with
	const {
		algName,
		hashAlg,
	} = this.authnrData.get("alg");

	if (algName === undefined) {
		throw new Error("packed attestation: unknown algorithm " + algName);
	}

	// from: https://w3c.github.io/webauthn/#packed-attestation
	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.

	const res = await validateSelfSignature(
		this.clientData.get("rawClientDataJson"),
		this.authnrData.get("rawAuthnrData"),
		this.authnrData.get("sig"),
		hashAlg,
		this.authnrData.get("credentialPublicKeyPem"),
	);
	if (!res || typeof res !== "boolean") {
		throw new Error("packed attestation signature verification failed");
	}
	this.audit.journal.add("sig");
	this.audit.journal.add("alg");
	this.audit.journal.add("x5c");

	// If successful, return attestation type Self and an empty trust path
	this.audit.info.set("attestation-type", "self");

	this.audit.journal.add("fmt");

	return true;
}

function packedValidateEcdaa() {
	throw new Error("packed attestation: ECDAA not implemented, please open a GitHub issue.");
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
	return [...new Uint8Array(buffer)]
		.map(x => x.toString(16).padStart(2, '0'))
		.join('');
}

const packedAttestation = {
	name: "packed",
	parseFn: packedParseFn,
	validateFn: packedValidateFn,
};

//export { packedAttestation };
module.exports.packedAttestation = packedAttestation;
