const base64 = require("@hexagon/base64").base64

function ab2str(buf) {
	let str = "";
	new Uint8Array(buf).forEach((ch) => {
		str += String.fromCharCode(ch);
	});
	return str;
}

function coerceToArrayBuffer(buf, name) {
	if (!name) {
		throw new TypeError("name not specified in coerceToArrayBuffer");
	}

	// Handle empty strings
	if (typeof buf === "string" && buf === "") {
		buf = new Uint8Array(0);

		// Handle base64url and base64 strings
	} else if (typeof buf === "string") {
		// base64 to base64url
		buf = buf.replace(/\+/g, "-").replace(/\//g, "_").replace("=", "");
		// base64 to Buffer
		//buf = tools.base64.toArrayBuffer(buf, true);
		buf = base64.toArrayBuffer(buf, true);
	}

	// Extract typed array from Array
	if (Array.isArray(buf)) {
		buf = new Uint8Array(buf);
	}

	// Extract ArrayBuffer from Node buffer
	if (typeof Buffer !== "undefined" && buf instanceof Buffer) {
		buf = new Uint8Array(buf);
		buf = buf.buffer;
	}

	// Extract arraybuffer from TypedArray
	if (buf instanceof Uint8Array) {
		buf = buf.slice(0, buf.byteLength, buf.buffer.byteOffset).buffer;
	}

	// error if none of the above worked
	if (!(buf instanceof ArrayBuffer)) {
		throw new TypeError(`could not coerce '${name}' to ArrayBuffer`);
	}

	return buf;
}

function isPem(pem) {
	if (typeof pem !== "string") {
		return false;
	}

	const pemRegex = /^-----BEGIN .+-----$\n([A-Za-z0-9+/=]|\n)*^-----END .+-----$/m;
	return !!pem.match(pemRegex);
}

function pemToBase64(pem) {
	
	// Clean up base64 string
	if (typeof pem === "string" || pem instanceof String) {
		pem = pem.replace(/\r/g, "");
	}
	
	if (!isPem(pem)) {
		throw new Error("expected PEM string as input");
	}

	// Remove trailing \n
	pem = pem.replace(/\n$/, "");

	// Split on \n
	let pemArr = pem.split("\n");

	// remove first and last lines
	pemArr = pemArr.slice(1, pemArr.length - 1);
	return pemArr.join("");
}

function coerceToBase64Url(thing, name) {
	if (!name) {
		throw new TypeError("name not specified in coerceToBase64");
	}

	if (typeof thing === "string") {
		// Convert from base64 to base64url
		thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/={0,2}$/g, "");
	}

	if (typeof thing !== "string") {
		try {
			thing = tools.base64.fromArrayBuffer(
				coerceToArrayBuffer(thing, name),
				true,
			);
		} catch (_err) {
			throw new Error(`could not coerce '${name}' to string`);
		}
	}

	return thing;
}

module.exports.ab2str = ab2str;
module.exports.isPem = isPem;
module.exports.pemToBase64 = pemToBase64;
module.exports.coerceToArrayBuffer = coerceToArrayBuffer;
module.exports.coerceToBase64Url = coerceToBase64Url;