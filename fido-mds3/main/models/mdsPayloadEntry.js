"use strict";
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
var dayjs_1 = __importDefault(require("dayjs"));
var MdsPayloadEntry = /** @class */ (function () {
    function MdsPayloadEntry(arg) {
        if (typeof arg === 'string') {
            var entry = JSON.parse(arg);
            this.entry = entry;
        }
        else {
            var entry = arg;
            this.entry = entry;
        }
    }
    MdsPayloadEntry.prototype.getPayloadEntry = function () {
        return this.entry;
    };
    MdsPayloadEntry.prototype.getAAGUID = function () {
        return this.entry.aaguid;
    };
    MdsPayloadEntry.prototype.getAAID = function () {
        return this.entry.aaid;
    };
    MdsPayloadEntry.prototype.getAttestationCertificateKeyIdentifiers = function () {
        return this.entry.attestationCertificateKeyIdentifiers;
    };
    MdsPayloadEntry.prototype.getLatestStatusReport = function () {
        var statusReports = __spreadArray([], this.entry.statusReports, true);
        statusReports.sort(function (a, b) {
            if (a.effectiveDate && b.effectiveDate) {
                var delta = (0, dayjs_1.default)(b.effectiveDate).unix() - (0, dayjs_1.default)(a.effectiveDate).unix();
                if (delta === 0) {
                    if (a.status === 'FIDO_CERTIFIED' && b.status === 'FIDO_CERTIFIED_L1') {
                        return 1;
                    }
                    else if (a.status === 'FIDO_CERTIFIED_L1' && b.status === 'FIDO_CERTIFIED') {
                        return -1;
                    }
                }
                return delta;
            }
            return -1;
        });
        return statusReports[0];
    };
    MdsPayloadEntry.prototype.getLatestAuthenticatorStatus = function () {
        return this.getLatestStatusReport().status;
    };
    return MdsPayloadEntry;
}());
exports.default = MdsPayloadEntry;