"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var fs_1 = __importDefault(require("fs"));
var path_1 = __importDefault(require("path"));
var axios_1 = __importDefault(require("axios"));
var base64url_1 = __importDefault(require("base64url"));
var comment_json_1 = require("comment-json");
var dayjs_1 = __importDefault(require("dayjs"));
var jsrsasign_1 = __importDefault(require("jsrsasign"));
var accessError_1 = __importDefault(require("./errors/accessError"));
/**
 * Accessor class executes accessing to metadata service.
 *
 */
var Accessor = /** @class */ (function () {
    function Accessor() {
    }
    Accessor.createPem = function (content, type) {
        var c;
        if (typeof content === 'string') {
            c = content;
        }
        else {
            c = content.toString('base64');
        }
        var pem = ["-----BEGIN ".concat(type, "-----"), c, "-----END ".concat(type, "-----")].join('\n');
        return pem;
    };
    /**
     * This method is expected to use in this class.
     *
     * @param url root certificate download endpoint
     * @returns root certificate's buffer
     */
    Accessor._requestRootCertificate = function (url) {
        return __awaiter(this, void 0, void 0, function () {
            var response, data;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, axios_1.default.get(url.toString(), { responseType: 'arraybuffer', })];
                    case 1:
                        response = _a.sent();
                        data = response.data;
                        if (!(data instanceof Buffer)) {
                            throw new accessError_1.default('Response data is not binary.');
                        }
                        return [2 /*return*/, data];
                }
            });
        });
    };
    /**
     * Detach root certificate info.
     */
    Accessor.detachRootCert = function () {
        Accessor.rootCert = undefined;
    };
    /**
     * Set root certificate info.
     *
     * @param pem PEM format certificate
     */
    Accessor.setRootCertPem = function (pem) {
        var certificate = new jsrsasign_1.default.X509(pem);
        Accessor.rootCert = certificate;
    };
    /**
     * Set root certificate info.
     *
     * @param filePath DER format certificate's file path
     */
    Accessor.setRootCertFile = function (filePath) {
        return __awaiter(this, void 0, void 0, function () {
            var buf, pem, certificate;
            return __generator(this, function (_a) {
                buf = fs_1.default.readFileSync(filePath);
                pem = Accessor.createPem(buf, 'CERTIFICATE');
                certificate = new jsrsasign_1.default.X509(pem);
                Accessor.rootCert = certificate;
                return [2 /*return*/];
            });
        });
    };
    /**
     * Set root certificate info.
     *
     * @param url certificate's URL
     */
    Accessor.setRootCertUrl = function (url) {
        return __awaiter(this, void 0, void 0, function () {
            var buf, pem, certificate, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        return [4 /*yield*/, Accessor._requestRootCertificate(url)];
                    case 1:
                        buf = _a.sent();
                        pem = Accessor.createPem(buf, 'CERTIFICATE');
                        certificate = new jsrsasign_1.default.X509(pem);
                        Accessor.rootCert = certificate;
                        return [3 /*break*/, 3];
                    case 2:
                        err_1 = _a.sent();
                        if (axios_1.default.isAxiosError(err_1) && err_1.response) {
                            throw new accessError_1.default("Request has error. Status code: ".concat(err_1.response.status));
                        }
                        throw err_1;
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Load metadata.
     *
     * @param blobJwt JWT format metadata
     */
    Accessor.fromJwt = function (blobJwt) {
        return __awaiter(this, void 0, void 0, function () {
            var _a, header, payload, signature, headerJSON, certPEMs, rsCerts, crlSNs, _i, _b, x5c, certPemString, rsCertificate, crlUris, snInArray, rootCert, configJson, defaultConfig, buf, pem, cert, err_2, buf, pem, cert, hasRevokedCert, isValidChain, i, cert, certStruct, algorithm, signatureHex, signature_1, upperCertPEM, alg, isValid, payloadString;
            var _this = this;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        _a = blobJwt.split('.'), header = _a[0], payload = _a[1], signature = _a[2];
                        if (!header || !payload || !signature) {
                            throw new accessError_1.default('Blob JWT is wrong format.');
                        }
                        headerJSON = JSON.parse(base64url_1.default.decode(header));
                        certPEMs = [];
                        rsCerts = [];
                        crlSNs = [];
                        _i = 0, _b = headerJSON['x5c'];
                        _c.label = 1;
                    case 1:
                        if (!(_i < _b.length)) return [3 /*break*/, 4];
                        x5c = _b[_i];
                        certPemString = Accessor.createPem(x5c, 'CERTIFICATE');
                        certPEMs.push(certPemString);
                        rsCertificate = new jsrsasign_1.default.X509(certPemString);
                        rsCerts.push(rsCertificate);
                        crlUris = rsCertificate.getExtCRLDistributionPointsURI() || [];
                        return [4 /*yield*/, Promise.all(crlUris.map(function (uri) { return __awaiter(_this, void 0, void 0, function () {
                                var res, crlPEM, crl, revSNs;
                                return __generator(this, function (_a) {
                                    switch (_a.label) {
                                        case 0: return [4 /*yield*/, axios_1.default.get(uri)];
                                        case 1:
                                            res = _a.sent();
                                            if (!res.data.startsWith('-----BEGIN')) return [3 /*break*/, 2];
                                            crlPEM = res.data;
                                            return [3 /*break*/, 4];
                                        case 2: return [4 /*yield*/, axios_1.default.get(uri, { responseType: 'arraybuffer' })];
                                        case 3:
                                            res = _a.sent();
                                            crlPEM = Accessor.createPem(Buffer.from(res.data), 'X509 CRL');
                                            _a.label = 4;
                                        case 4:
                                            crl = new jsrsasign_1.default.X509CRL(crlPEM);
                                            revSNs = crl.getRevCertArray().map(function (revCert) {
                                                return revCert.sn.hex;
                                            }) || [];
                                            return [2 /*return*/, revSNs];
                                    }
                                });
                            }); }))];
                    case 2:
                        snInArray = (_c.sent()) || [[]];
                        crlSNs = __spreadArray(__spreadArray([], crlSNs, true), snInArray.flat(), true);
                        _c.label = 3;
                    case 3:
                        _i++;
                        return [3 /*break*/, 1];
                    case 4:
                        rootCert = Accessor.rootCert;
                        if (!!rootCert) return [3 /*break*/, 8];
                        configJson = fs_1.default.readFileSync(path_1.default.resolve(__dirname, '../config/config.json'), 'utf-8');
                        defaultConfig = (0, comment_json_1.parse)(configJson);
                        _c.label = 5;
                    case 5:
                        _c.trys.push([5, 6, , 8]);
                        buf = fs_1.default.readFileSync(path_1.default.resolve(__dirname, defaultConfig.root.file));
                        pem = Accessor.createPem(buf, 'CERTIFICATE');
                        cert = new jsrsasign_1.default.X509(pem);
                        if ((0, dayjs_1.default)().isAfter((0, dayjs_1.default)(jsrsasign_1.default.zulutomsec(cert.getNotBefore()))) && (0, dayjs_1.default)().isBefore((0, dayjs_1.default)(jsrsasign_1.default.zulutomsec(cert.getNotAfter())))) {
                            rootCert = cert;
                        }
                        else {
                            throw new Error('Root certificate file in this module is not valid.');
                        }
                        return [3 /*break*/, 8];
                    case 6:
                        err_2 = _c.sent();
                        return [4 /*yield*/, Accessor._requestRootCertificate(new URL(defaultConfig.root.url))];
                    case 7:
                        buf = _c.sent();
                        pem = Accessor.createPem(buf, 'CERTIFICATE');
                        cert = new jsrsasign_1.default.X509(pem);
                        rootCert = cert;
                        fs_1.default.writeFileSync(defaultConfig.root.file, buf);
                        return [3 /*break*/, 8];
                    case 8:
                        rsCerts.push(rootCert);
                        certPEMs.push(Accessor.createPem(Buffer.from(rootCert.hex, 'hex'), 'CERTIFICATE'));
                        hasRevokedCert = rsCerts.some(function (c) {
                            var sn = c.getSerialNumberHex();
                            return crlSNs.includes(sn);
                        });
                        if (hasRevokedCert) {
                            throw new accessError_1.default('Revoked certificate is included.');
                        }
                        isValidChain = true;
                        for (i = 0; i < rsCerts.length - 1; i++) {
                            cert = rsCerts[i];
                            certStruct = jsrsasign_1.default.ASN1HEX.getTLVbyList(cert.hex, 0, [0]);
                            if (certStruct == null) {
                                isValidChain = false;
                                break;
                            }
                            algorithm = cert.getSignatureAlgorithmField();
                            signatureHex = cert.getSignatureValueHex();
                            signature_1 = new jsrsasign_1.default.KJUR.crypto.Signature({ alg: algorithm });
                            upperCertPEM = certPEMs[i + 1];
                            signature_1.init(upperCertPEM);
                            signature_1.updateHex(certStruct);
                            isValidChain = isValidChain && signature_1.verify(signatureHex);
                        }
                        if (!isValidChain) {
                            throw new accessError_1.default('Certificate chain cannot be verified.');
                        }
                        alg = headerJSON['alg'];
                        isValid = jsrsasign_1.default.KJUR.jws.JWS.verifyJWT(blobJwt, certPEMs[0], { alg: [alg] });
                        if (!isValid) {
                            throw new accessError_1.default('JWS cannot be verified.');
                        }
                        Accessor.alg = alg;
                        payloadString = base64url_1.default.decode(payload);
                        Accessor.payloadData = payloadString;
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Load metadata.
     *
     * @param filePath JWT format file's path
     */
    Accessor.fromFile = function (filePath) {
        return __awaiter(this, void 0, void 0, function () {
            var jwtStr;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        jwtStr = fs_1.default.readFileSync(filePath, 'utf-8');
                        return [4 /*yield*/, Accessor.fromJwt(jwtStr)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Load metadata.
     *
     * @param url metadata's endpoint URL
     */
    Accessor.fromUrl = function (url) {
        return __awaiter(this, void 0, void 0, function () {
            var mdsResponse;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, axios_1.default.get(url.toString())];
                    case 1:
                        mdsResponse = _a.sent();
                        return [4 /*yield*/, Accessor.fromJwt(mdsResponse.data)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Return metadata payload.
     *
     * @returns metadata in JSON Object
     */
    Accessor.toJsonObject = function () {
        if (!Accessor.payloadData) {
            throw new accessError_1.default('Payload Data is not found.');
        }
        return JSON.parse(Accessor.payloadData);
    };
    /**
     * Return metadata payload.
     *
     * @param filePath write metadata payload in this file
     */
    Accessor.toFile = function (filePath) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                if (!Accessor.payloadData) {
                    throw new accessError_1.default('Payload Data is not found.');
                }
                fs_1.default.writeFileSync(filePath, Accessor.payloadData);
                return [2 /*return*/];
            });
        });
    };
    Accessor.getAlg = function () {
        return Accessor.alg;
    };
    return Accessor;
}());
exports.default = Accessor;