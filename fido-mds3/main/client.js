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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var dayjs_1 = __importDefault(require("dayjs"));
var fs_1 = __importDefault(require("fs"));
var mdsPayloadEntry_1 = __importDefault(require("./models/mdsPayloadEntry"));
var invalidParameterError_1 = __importDefault(require("./errors/invalidParameterError"));
var settingError_1 = __importDefault(require("./errors/settingError"));
var oldDataError_1 = __importDefault(require("./errors/oldDataError"));
var accessor_1 = __importDefault(require("./accessor"));
/**
 * Client class finds authenticator information from metadata service by authenticator model identifier(AAGUID etc.).
 *
 */
var Client = /** @class */ (function () {
    /**
     * Client class constructor.
     * This constructor does not load authenticator model infos yet.
     * Please compare to create method.
     *
     * @param config
     */
    function Client(config) {
        this.config = config;
    }
    /**
     * Create the instance of client class and load authenticator model infos.
     * Please compare to constructor.
     *
     * @param config
     * @returns Instance of client class
     */
    Client.create = function (config) {
        return __awaiter(this, void 0, void 0, function () {
            var client;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        client = new Client(config);
                        return [4 /*yield*/, client.load()];
                    case 1:
                        _a.sent();
                        return [2 /*return*/, client];
                }
            });
        });
    };
    /**
     * Updates authenticator model infos.
     */
    Client.prototype.refresh = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.load()];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    Client.prototype.format = function (payloadJSON) {
        var entriesJSONArray = payloadJSON['entries'];
        this.entries = [];
        for (var _i = 0, entriesJSONArray_1 = entriesJSONArray; _i < entriesJSONArray_1.length; _i++) {
            var ent = entriesJSONArray_1[_i];
            this.entries.push(ent); // XXX danger, should validate entry?
        }
        this.updatedAt = (0, dayjs_1.default)().toDate();
        this.legalHeader = payloadJSON['legalHeader'];
        this.no = payloadJSON['no'];
        this.nextUpdateAt = (0, dayjs_1.default)(payloadJSON['nextUpdate'], 'YYYY-MM-DD').toDate();
    };
    Client.prototype.append = function (statementJSON) {
        if(!this.entries || 0 == this.entries.length){
            throw new settingError_1.default('have to call format method first.');
        }
        this.entries.push(statementJSON); // XXX danger, should validate entry?        
    };
    Client.prototype.getEntries = function () {
        return this.entries;
    };
    /**
     * Load authenticator infos to this instance, following config.
     *
     */
    Client.prototype.load = function () {
        return __awaiter(this, void 0, void 0, function () {
            var _a, _b, jwtStr, data;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        // set root certificate
                        accessor_1.default.detachRootCert();
                        _a = this.config.accessRootCertificate;
                        switch (_a) {
                            case 'url': return [3 /*break*/, 1];
                            case 'file': return [3 /*break*/, 3];
                            case 'pem': return [3 /*break*/, 5];
                        }
                        return [3 /*break*/, 6];
                    case 1: return [4 /*yield*/, accessor_1.default.setRootCertUrl(this.config.rootUrl)];
                    case 2:
                        _c.sent();
                        return [3 /*break*/, 7];
                    case 3: return [4 /*yield*/, accessor_1.default.setRootCertFile(this.config.rootFile)];
                    case 4:
                        _c.sent();
                        return [3 /*break*/, 7];
                    case 5:
                        if (!this.config.rootPem) {
                            throw new settingError_1.default('Please set root certificate pem.');
                        }
                        accessor_1.default.setRootCertPem(this.config.rootPem);
                        return [3 /*break*/, 7];
                    case 6: throw new settingError_1.default('Please set how to access root certificate.');
                    case 7:
                        _b = this.config.accessMds;
                        switch (_b) {
                            case 'url': return [3 /*break*/, 8];
                            case 'file': return [3 /*break*/, 10];
                            case 'jwt': return [3 /*break*/, 12];
                        }
                        return [3 /*break*/, 14];
                    case 8: return [4 /*yield*/, accessor_1.default.fromUrl(this.config.mdsUrl)];
                    case 9:
                        _c.sent();
                        return [3 /*break*/, 15];
                    case 10:
                        jwtStr = fs_1.default.readFileSync(this.config.mdsFile, 'utf-8');
                        return [4 /*yield*/, accessor_1.default.fromJwt(jwtStr)];
                    case 11:
                        _c.sent();
                        return [3 /*break*/, 15];
                    case 12:
                        if (!this.config.mdsJwt) {
                            throw new settingError_1.default('Please set mds jwt.');
                        }
                        return [4 /*yield*/, accessor_1.default.fromJwt(this.config.mdsJwt)];
                    case 13:
                        _c.sent();
                        return [3 /*break*/, 15];
                    case 14: throw new settingError_1.default('Please set how to access MDS.');
                    case 15: return [4 /*yield*/, accessor_1.default.toFile(this.config.payloadFile)];
                    case 16:
                        _c.sent(); // deprecated
                        data = accessor_1.default.toJsonObject();
                        this.format(data);
                        return [2 /*return*/];
                }
            });
        });
    };
    Client.prototype.judgeRefresh = function (refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var option;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        option = 'needed';
                        if (typeof refresh === 'boolean') {
                            option = refresh ? 'force' : 'needed';
                        }
                        else if (refresh != null) {
                            option = refresh;
                        }
                        if (!(option === 'force')) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.refresh()];
                    case 1:
                        _a.sent();
                        return [3 /*break*/, 5];
                    case 2:
                        if (!(option === 'needed' && (!this.entries || (this.nextUpdateAt && (0, dayjs_1.default)(this.nextUpdateAt).isBefore((0, dayjs_1.default)()))))) return [3 /*break*/, 4];
                        return [4 /*yield*/, this.refresh()];
                    case 3:
                        _a.sent();
                        return [3 /*break*/, 5];
                    case 4:
                        if (option === 'error' && (!this.entries || (this.nextUpdateAt && (0, dayjs_1.default)(this.nextUpdateAt).isBefore((0, dayjs_1.default)())))) {
                            throw new oldDataError_1.default("Metadata is old. Update at ".concat(this.nextUpdateAt && (0, dayjs_1.default)(this.nextUpdateAt).toISOString()), this.nextUpdateAt);
                        }
                        _a.label = 5;
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Find FIDO2 authenticator info by AAGUID.
     *
     * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
     * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
     * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
     *
     * @param aaguid FIDO2 authenticator AAGUID
     * @param refresh if true force to fetch Metadata BLOB, if false depends on update date or follows FM3RefreshOption
     * @returns Metadata entry if not find return null
     */
    Client.prototype.findByAAGUID = function (aaguid, refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var _i, _a, ent, ms;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        if (!aaguid) {
                            throw new invalidParameterError_1.default('"aaguid" is empty.');
                        }
                        return [4 /*yield*/, this.judgeRefresh(refresh)];
                    case 1:
                        _b.sent();
                        if (!this.entries) {
                            throw new settingError_1.default('Metadata cannot be fetched.');
                        }
                        var the_id = aaguid && typeof aaguid === 'string' ? aaguid : buf2hex(aaguid)
                        for (_i = 0, _a = this.entries; _i < _a.length; _i++) {
                            ent = _a[_i];
                            const ent_id = ent.aaguid ? ent.aaguid.replaceAll('-', ''): null
                            //console.log('ent.aaguid='+ent_id)
                            if ( ent_id && ent_id === the_id) {
                                return [2 /*return*/, ent];
                            }
                            else {
                                ms = ent.metadataStatement;
                                if (ms && ms.aaguid === the_id) {
                                    return [2 /*return*/, ent];
                                }
                            }
                        }
                        return [2 /*return*/, null];
                }
            });
        });
    };
    /**
     * Find FIDO2 authenticator info class by AAGUID and return in model class .
     *
     * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
     * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
     * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
     *
     * @param aaguid FIDO2 authenticator AAGUID
     * @param refresh if true force to fetch Metadata BLOB, if false depends on update date or follows FM3RefreshOption
     * @returns Metadata entry model class if not find return null
     */
    Client.prototype.findModelByAAGUID = function (aaguid, refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var entry;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.findByAAGUID(aaguid, refresh)];
                    case 1:
                        entry = _a.sent();
                        if (entry) {
                            return [2 /*return*/, new mdsPayloadEntry_1.default(entry)];
                        }
                        return [2 /*return*/, null];
                }
            });
        });
    };
    /**
     * Find FIDO UAF authenticator info by AAID.
     *
     * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
     * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
     * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
     *
     * @param aaid FIDO UAF authenticator AAID
     * @param refresh if true force to fetch Metadata BLOB, if false depends on update date or follows FM3RefreshOption
     * @returns Metadata entry if not find return null
     */
    Client.prototype.findByAAID = function (aaid, refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var _i, _a, ent, ms;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        if (!aaid) {
                            throw new invalidParameterError_1.default('"aaid" is empty.');
                        }
                        return [4 /*yield*/, this.judgeRefresh(refresh)];
                    case 1:
                        _b.sent();
                        if (!this.entries) {
                            throw new settingError_1.default('Metadata cannot be fetched.');
                        }
                        for (_i = 0, _a = this.entries; _i < _a.length; _i++) {
                            ent = _a[_i];
                            if (ent.aaid === aaid) {
                                return [2 /*return*/, ent];
                            }
                            else {
                                ms = ent.metadataStatement;
                                if (ms && ms.aaid === aaid) {
                                    return [2 /*return*/, ent];
                                }
                            }
                        }
                        return [2 /*return*/, null];
                }
            });
        });
    };
    /**
     * Find FIDO UAF authenticator info by AAID and return in model class.
     *
     * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
     * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
     * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
     *
     * @param aaid FIDO UAF authenticator AAID
     * @param refresh if true force to fetch Metadata BLOB, if false depends on update date or follows FM3RefreshOption
     * @returns Metadata entry model class if not find return null
     */
    Client.prototype.findModelByAAID = function (aaid, refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var entry;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.findByAAID(aaid, refresh)];
                    case 1:
                        entry = _a.sent();
                        if (entry) {
                            return [2 /*return*/, new mdsPayloadEntry_1.default(entry)];
                        }
                        return [2 /*return*/, null];
                }
            });
        });
    };
    /**
     * Find FIDO U2F authenticator info by AttestationCertificateKeyIdentifier.
     *
     * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
     * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
     * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
     *
     * @param attestationCertificateKeyIdentifier FIDO U2F authenticator AttestationCertificateKeyIdentifier
     * @param refresh if true force to fetch Metadata BLOB, if false depends on update date or follows FM3RefreshOption
     * @returns Metadata entry if not find return null
     */
    Client.prototype.findByAttestationCertificateKeyIdentifier = function (attestationCertificateKeyIdentifier, refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var _i, _a, ent, ms;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        if (!attestationCertificateKeyIdentifier) {
                            throw new invalidParameterError_1.default('"attestationCertificateKeyIdentifiers" is empty.');
                        }
                        return [4 /*yield*/, this.judgeRefresh(refresh)];
                    case 1:
                        _b.sent();
                        if (!this.entries) {
                            throw new settingError_1.default('Metadata cannot be fetched.');
                        }
                        for (_i = 0, _a = this.entries; _i < _a.length; _i++) {
                            ent = _a[_i];
                            if (!ent.attestationCertificateKeyIdentifiers) {
                                continue;
                            }
                            if (ent.attestationCertificateKeyIdentifiers.some(function (aki) { return aki === attestationCertificateKeyIdentifier; })) {
                                return [2 /*return*/, ent];
                            }
                            else {
                                ms = ent.metadataStatement;
                                if (ms && ms.attestationCertificateKeyIdentifiers && ms.attestationCertificateKeyIdentifiers.some(function (aki) { return aki === attestationCertificateKeyIdentifier; })) {
                                    return [2 /*return*/, ent];
                                }
                            }
                        }
                        return [2 /*return*/, null];
                }
            });
        });
    };
    /**
     * Find FIDO U2F authenticator info by AttestationCertificateKeyIdentifier and return in model class .
     *
     * Note: FIDO UAF authenticators support AAID, but they don’t support AAGUID.<br/>
     * Note: FIDO2 authenticators support AAGUID, but they don’t support AAID.<br/>
     * Note: FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.<br/>
     *
     * @param attestationCertificateKeyIdentifier FIDO U2F authenticator AttestationCertificateKeyIdentifier
     * @param refresh if true force to fetch Metadata BLOB, if false depends on update date or follows FM3RefreshOption
     * @returns Metadata entry model class if not find return null
     */
    Client.prototype.findModelByAttestationCertificateKeyIdentifier = function (attestationCertificateKeyIdentifier, refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var entry;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.findByAttestationCertificateKeyIdentifier(attestationCertificateKeyIdentifier, refresh)];
                    case 1:
                        entry = _a.sent();
                        if (entry) {
                            return [2 /*return*/, new mdsPayloadEntry_1.default(entry)];
                        }
                        return [2 /*return*/, null];
                }
            });
        });
    };
    /**
     * Find FIDO(FIDO2, FIDO UAF and FIDO U2F) authenticator info.
     *
     * @param identifier AAGUID, AAID or AttestationCertificateKeyIdentifier
     * @param refresh if true force to fetch Metadata BLOB, if false depends on update date or follows FM3RefreshOption
     * @returns Metadata entry if not find return null
     */
    Client.prototype.findMetadata = function (identifier, refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var findFunctions, isAlreadyRefresh, _i, findFunctions_1, func, option, ent;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        findFunctions = [this.findByAAGUID, this.findByAAID, this.findByAttestationCertificateKeyIdentifier];
                        isAlreadyRefresh = false;
                        _i = 0, findFunctions_1 = findFunctions;
                        _a.label = 1;
                    case 1:
                        if (!(_i < findFunctions_1.length)) return [3 /*break*/, 4];
                        func = findFunctions_1[_i];
                        option = void 0;
                        switch (refresh) {
                            case 'error':
                                option = 'error';
                                break;
                            case 'force':
                            case true:
                                option = isAlreadyRefresh ? 'needed' : 'force';
                                break;
                            case 'needed':
                            case false:
                            default:
                                option = 'needed';
                        }
                        return [4 /*yield*/, func.call(this, identifier, option)];
                    case 2:
                        ent = _a.sent();
                        if (ent) {
                            return [2 /*return*/, ent];
                        }
                        isAlreadyRefresh = true;
                        _a.label = 3;
                    case 3:
                        _i++;
                        return [3 /*break*/, 1];
                    case 4: return [2 /*return*/, null];
                }
            });
        });
    };
    /**
     * Find FIDO(FIDO2, FIDO UAF and FIDO U2F) authenticator info and return in model class .
     *
     * @param identifier AAGUID, AAID or AttestationCertificateKeyIdentifier
     * @param refresh if true force to fetch Metadata BLOB, if false depends on update date or follows FM3RefreshOption
     * @returns Metadata entry model class if not find return null
     */
    Client.prototype.findMetadataModel = function (identifier, refresh) {
        return __awaiter(this, void 0, void 0, function () {
            var entry;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.findMetadata(identifier, refresh)];
                    case 1:
                        entry = _a.sent();
                        if (entry) {
                            return [2 /*return*/, new mdsPayloadEntry_1.default(entry)];
                        }
                        return [2 /*return*/, null];
                }
            });
        });
    };
    return Client;
}());

function buf2hex(buffer) { // buffer is an ArrayBuffer
return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}

exports.default = Client;