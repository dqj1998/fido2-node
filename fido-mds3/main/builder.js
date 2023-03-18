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
var fs_1 = __importDefault(require("fs"));
var path_1 = __importDefault(require("path"));
var comment_json_1 = require("comment-json");
var invalidParameterError_1 = __importDefault(require("./errors/invalidParameterError"));
var client_1 = __importDefault(require("./client"));
/**
 * Builder class builds Client class which finds authenticator's information, following config.
 */
var Builder = /** @class */ (function () {
    /**
     * Builder class constructor.
     *
     * @constructor
     * @param config
     */
    function Builder(config) {
        var configJson = fs_1.default.readFileSync(path_1.default.resolve(__dirname, '../config/config.json'), 'utf-8');
        var defaultConfig = (0, comment_json_1.parse)(configJson);
        if (config && !config.accessMds) {
            if (config.mdsUrl && !config.mdsFile && !config.mdsJwt) {
                config.accessMds = 'url';
            }
            else if (!config.mdsUrl && config.mdsFile && !config.mdsJwt) {
                config.accessMds = 'file';
            }
            else if (!config.mdsUrl && !config.mdsFile && config.mdsJwt) {
                config.accessMds = 'jwt';
            }
        }
        if (config && !config.accessRootCertificate) {
            if (config.rootUrl && !config.rootFile && !config.rootPem) {
                config.accessRootCertificate = 'url';
            }
            else if (!config.rootUrl && config.rootFile && !config.rootPem) {
                config.accessRootCertificate = 'file';
            }
            else if (!config.rootUrl && !config.rootFile && config.rootPem) {
                config.accessRootCertificate = 'pem';
            }
        }
        this.config = {
            mdsUrl: (config && config.mdsUrl) || new URL(defaultConfig.mds.url),
            mdsFile: (config && config.mdsFile) || path_1.default.resolve(__dirname, defaultConfig.mds.file),
            mdsJwt: (config && config.mdsJwt) || undefined,
            payloadFile: (config && config.payloadFile) || path_1.default.resolve(__dirname, defaultConfig.payload.file),
            rootUrl: (config && config.rootUrl) || new URL(defaultConfig.root.url),
            rootFile: (config && config.rootFile) || path_1.default.resolve(__dirname, defaultConfig.root.file),
            rootPem: (config && config.rootPem) || undefined,
            accessMds: (config && config.accessMds) || defaultConfig.mds.access,
            accessRootCertificate: (config && config.accessRootCertificate) || defaultConfig.root.access,
        };
    }
    /**
     * Set metadata service URL.
     *
     * @param mdsUrl Metadata service URL
     * @returns Builder class
     */
    Builder.prototype.mdsUrl = function (mdsUrl) {
        if (!mdsUrl) {
            throw new invalidParameterError_1.default('"mdsUrl" is empty.');
        }
        this.config.mdsUrl = mdsUrl;
        this.config.accessMds = 'url';
        return this;
    };
    /**
     * Set metadata service JWT file path.
     *
     * @param mdsFile Metadata service JWT file path
     * @returns Builder class
     */
    Builder.prototype.mdsFile = function (mdsFile) {
        if (!mdsFile) {
            throw new invalidParameterError_1.default('"mdsFile" is empty.');
        }
        this.config.mdsFile = mdsFile;
        this.config.accessMds = 'file';
        return this;
    };
    /**
     * Set metadata service JWT string.
     *
     * @param mdsJwt Metadata service JWT string
     * @returns Builder class
     */
    Builder.prototype.mdsJwt = function (mdsJwt) {
        if (!mdsJwt) {
            throw new invalidParameterError_1.default('"mdsJwt" is empty.');
        }
        this.config.mdsJwt = mdsJwt;
        this.config.accessMds = 'jwt';
        return this;
    };
    /**
     * Set file path which metadata service payload is saved in.
     *
     * @deprecated
     * @param payloadFile Metadata service payload file path
     * @returns Builder class
     */
    Builder.prototype.payloadFile = function (payloadFile) {
        if (!payloadFile) {
            throw new invalidParameterError_1.default('"payloadFile" is empty.');
        }
        this.config.payloadFile = payloadFile;
        return this;
    };
    /**
     * Set metadata service root certificate file URL.
     *
     * @param rootUrl Metadata service root certificate file URL
     * @returns Builder class
     */
    Builder.prototype.rootUrl = function (rootUrl) {
        if (!rootUrl) {
            throw new invalidParameterError_1.default('"rootUrl" is empty.');
        }
        this.config.rootUrl = rootUrl;
        this.config.accessRootCertificate = 'url';
        return this;
    };
    /**
     * Set metadata service root certificate file path.
     *
     * @param rootFile Metadata service root certificate file
     * @returns Builder class
     */
    Builder.prototype.rootFile = function (rootFile) {
        if (!rootFile) {
            throw new invalidParameterError_1.default('"rootFile" is empty.');
        }
        this.config.rootFile = rootFile;
        this.config.accessRootCertificate = 'file';
        return this;
    };
    /**
     * Set metadata service root certificate PEM.
     *
     * @param rootPem Metadata service root certificate PEM
     * @returns Builder class
     */
    Builder.prototype.rootPem = function (rootPem) {
        if (!rootPem) {
            throw new invalidParameterError_1.default('"rootPem" is empty.');
        }
        this.config.rootPem = rootPem;
        this.config.accessRootCertificate = 'pem';
        return this;
    };
    /**
     * Build client class.
     * Client class which is returned by this method does not prepare authenticator info yet.
     * Please compare to buildAsync method.
     *
     * @returns Client class
     */
    Builder.prototype.build = function () {
        return new client_1.default(this.config);
    };
    /**
     * Build client class.
     * Client class which is returned by this method already prepare authenticator info.
     * Please compare to build method.
     *
     * @returns Client class
     */
    Builder.prototype.buildAsync = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, client_1.default.create(this.config)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return Builder;
}());
exports.default = Builder;