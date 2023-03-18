"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var baseError_1 = require("./baseError");
/**
 * Setting(default configure, file download, file save or certification validation) is invalid.
 */
var FM3SettingError = /** @class */ (function (_super) {
    __extends(FM3SettingError, _super);
    function FM3SettingError(message) {
        var _this = _super.call(this, message) || this;
        _this.name = 'FM3SettingError';
        return _this;
    }
    return FM3SettingError;
}(baseError_1.FM3BaseError));
exports.default = FM3SettingError;