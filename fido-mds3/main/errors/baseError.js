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
exports.FM3BaseError = void 0;
var FM3BaseError = /** @class */ (function (_super) {
    __extends(FM3BaseError, _super);
    function FM3BaseError(message) {
        var _this = _super.call(this, message) || this;
        _this.name = 'FM3BaseError';
        return _this;
    }
    return FM3BaseError;
}(Error));
exports.FM3BaseError = FM3BaseError;