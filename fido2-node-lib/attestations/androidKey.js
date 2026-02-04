const { arrayBufferEquals, abToPem, appendBuffer, coerceToArrayBuffer, coerceToBase64, tools } = require("../utils.js")

const { Certificate, CertManager } = require("../certUtils.js")

const PublicKey = require("../keyUtils.js")

// Supported algorithms for android-key attestation
const algMap = new Map([
	[-7, {
		algName: "ECDSA_w_SHA256",
		hashAlg: "SHA-256",
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
	[-258, {
		algName: "RSASSA-PKCS1-v1_5_w_SHA384",
		hashAlg: "SHA-384",
	}],
	[-259, {
		algName: "RSASSA-PKCS1-v1_5_w_SHA512",
		hashAlg: "SHA-512",
	}],
]);

/**
 * Parse android-key attestation statement
 * Based on: https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
 */
function androidKeyParseFn(attStmt) {
	const ret = new Map();

	// alg - COSE algorithm identifier
	const algEntry = algMap.get(attStmt.alg);
	if (algEntry === undefined) {
		throw new Error("android-key attestation: unknown algorithm: " + attStmt.alg);
	}
	ret.set("alg", algEntry);

	// sig - signature bytes
	let sig = attStmt.sig;
	sig = coerceToArrayBuffer(sig, "android-key signature");
	ret.set("sig", sig);

	// x5c - certificate chain
	const x5c = attStmt.x5c;
	if (!Array.isArray(x5c) || x5c.length === 0) {
		throw new Error("android-key attestation: x5c must be a non-empty array");
	}

	const newX5c = [];
	for (let cert of x5c) {
		cert = coerceToArrayBuffer(cert, "android-key x5c cert");
		newX5c.push(cert);
	}
	
	// First certificate is the attestation certificate
	ret.set("attCert", newX5c.shift());
	// Remaining certificates form the chain
	ret.set("x5c", newX5c);

	return ret;
}

/**
 * Validate android-key attestation
 * Based on: https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
 */
async function androidKeyValidateFn() {
	// Get algorithm info
	const {
		algName,
		hashAlg,
	} = this.authnrData.get("alg");

	if (algName === undefined) {
		throw new Error("android-key attestation: unknown algorithm " + algName);
	}

	// Step 1: Verify that sig is a valid signature over the concatenation of 
	// authenticatorData and clientDataHash using the attestation public key in 
	// attestation certificate with the algorithm specified in alg
	const res = await validateSignature(
		this.clientData.get("rawClientDataJson"),
		this.authnrData.get("rawAuthnrData"),
		this.authnrData.get("sig"),
		hashAlg,
		this.authnrData.get("attCert"),
	);
	
	if (!res) {
		throw new Error("android-key attestation signature verification failed");
	}
	
	this.audit.journal.add("sig");
	this.audit.journal.add("alg");

	// Step 2: Verify that the public key in the first certificate in x5c matches 
	// the credentialPublicKey in the attestedCredentialData in authenticatorData
	const attCert = new Certificate(coerceToBase64(this.authnrData.get("attCert"), "attCert"));
	
	// Get credential public key from attestation data
	const credentialPublicKey = new PublicKey();
	await credentialPublicKey.fromPem(
		this.authnrData.get("credentialPublicKeyPem")
	);

	// Get public key from certificate
	const certificatePublicKey = new PublicKey();
	certificatePublicKey.fromCryptoKey(await attCert.getPublicKey());
	
	// Compare by re-exporting both to PEM format
	const credentialPublicKeyPem = await credentialPublicKey.toPem(true);
	const certificatePublicKeyPem = await certificatePublicKey.toPem(true);
	
	this.audit.journal.add("credentialPublicKeyPem");
	
	if (credentialPublicKeyPem !== certificatePublicKeyPem) {
		throw new Error("android-key attestation: certificate public key does not match credential public key");
	}

	// Step 3: Verify that the attestation certificate meets the requirements
	// The certificate MUST be a valid X.509 certificate and MUST use SHA-256 as hash algorithm
	// Note: We do basic validation here. Full certificate chain validation would require
	// Google's root certificates which are not always available
	
	await validateCert(attCert, this.audit);

	// Add attestation certificate to audit
	this.audit.journal.add("attCert");
	this.audit.journal.add("x5c");

	// If successful, return attestation type Basic
	this.audit.info.set("attestation-type", "basic");
	this.audit.journal.add("fmt");

	return true;
}

/**
 * Validate the signature
 */
async function validateSignature(
	rawClientData,
	authenticatorData,
	sig,
	hashAlg,
	parsedAttCert,
) {
	// Create clientDataHash
	const hash = await tools.hashDigest(rawClientData);
	const clientDataHash = new Uint8Array(hash).buffer;

	// Convert cert to PEM
	const attCertPem = abToPem("CERTIFICATE", parsedAttCert);

	// Get public key from cert
	const cert = new Certificate(attCertPem);
	const publicKey = await cert.getPublicKey();

	// Verify signature over authenticatorData || clientDataHash
	const verify = await tools.verifySignature(
		publicKey,
		sig,
		appendBuffer(authenticatorData, clientDataHash),
		hashAlg,
	);
	
	return verify;
}

/**
 * Validate attestation certificate
 */
async function validateCert(attCert, audit) {
	// Get certificate subject
	const subject = attCert.getSubject();
	
	// Store certificate info in audit
	if (subject.has("common-name")) {
		audit.info.set("common-name", subject.get("common-name"));
	}
	if (subject.has("organization-name")) {
		audit.info.set("organization-name", subject.get("organization-name"));
	}

	// Verify certificate is not expired
	const now = Date.now();

	if (attCert._cert && attCert._cert.notBefore && attCert._cert.notBefore.value > now) {
		throw new Error("android-key attestation: certificate is not yet valid");
	}

	if (attCert._cert && attCert._cert.notAfter && attCert._cert.notAfter.value < now) {
		throw new Error("android-key attestation: certificate has expired");
	}

	// Note: Full certificate chain validation against Google root CAs would go here
	// For now, we perform basic validation only
	audit.warning.set("android-key-validation", 
		"Full certificate chain validation not implemented. Only basic validation performed.");

	return true;
}

const androidKeyAttestation = {
	name: "android-key",
	parseFn: androidKeyParseFn,
	validateFn: androidKeyValidateFn,
};

module.exports.androidKeyAttestation = androidKeyAttestation;
