
function _toBase64URL(s) {
    return (s = (s = (s = s.split("=")[0]).replace(/\+/g, "-")).replace(/\//g, "_"));
}

function _base64ToArrayBuffer(base64) {
    var binary_string =  window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++)        {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

function _fromBase64URL(s) {
    var chk = (s = s.replace(/-/g, "+").replace(/_/g, "/")).length % 4;
    if (chk) {
        if (1 === chk) throw new Error("Base64url string is wrong.");
        s += new Array(5 - chk).join("=");
    }
    return s;
}

function _bufferToString(s) {
    return new Uint8Array(s).reduce((s, e) => s + String.fromCodePoint(e), "");
}
