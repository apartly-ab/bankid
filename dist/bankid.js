"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BankIdClient = exports.RequestError = exports.BankIdError = exports.BankIdMethod = exports.REQUEST_FAILED_ERROR = exports.BankIdErrorCode = exports.cancelSchema = exports.signRequestSchema = exports.phoneAuthSchema = exports.authRequestSchema = void 0;
const fs = __importStar(require("fs"));
const https = __importStar(require("https"));
const path = __importStar(require("path"));
const axios_1 = __importDefault(require("axios"));
const zod_1 = require("zod");
//
// Type definitions for /auth
//
const authOptionalRequirementsSchema = zod_1.z.object({
    pinCode: zod_1.z.boolean().optional(),
    mrtd: zod_1.z.boolean().optional(),
    cardReader: zod_1.z.literal("class1").or(zod_1.z.literal("class2")).optional(),
    certificatePolicies: zod_1.z.array(zod_1.z.string()).optional(),
    personalNumber: zod_1.z.string().optional(),
}).optional();
const userVisibleDataSchema = zod_1.z.string().refine((s) => {
    try {
        const correctSize = Buffer.from(s, "base64").length <= 40000;
        const correctEncoding = Buffer.from(s, "base64").toString("base64") === s;
        return correctSize && correctEncoding;
    }
    catch (e) {
        return false;
    }
}, "userVisibleData must be base64 encoded, 1-40000 characters in its base64 encoded state");
const userNonVisibleDataSchema = zod_1.z.string().refine((s) => {
    try {
        return Buffer.from(s, "base64").length <= 200000;
    }
    catch (e) {
        return false;
    }
}, "userVisibleData must be base64 encoded, 1-200000 characters in its base64 encoded state");
exports.authRequestSchema = zod_1.z.object({
    endUserIp: zod_1.z.string(),
    personalNumber: zod_1.z.string().optional(),
    requirement: authOptionalRequirementsSchema,
    //userVisibleData, if present, must be encoded as UTF-8 and then base 64 encoded. 1 – 40,000 characters after base 64 encoding
    userVisibleData: userVisibleDataSchema.optional(),
    //userNonVisibleData, if present, must be base64 encoded, 1-200000 characters in its base64 encoded state
    userNonVisibleData: userNonVisibleDataSchema.optional(),
    userVisibleDataFormat: zod_1.z.literal("simpleMarkdownV1").optional(),
});
exports.phoneAuthSchema = exports.authRequestSchema.extend({
    personalNumber: zod_1.z.string(),
    callInitiator: zod_1.z.literal("user").or(zod_1.z.literal("RP"))
});
exports.signRequestSchema = exports.authRequestSchema.extend({
    userVisibleData: userVisibleDataSchema,
});
//
// Type definitions for /collect
//
const collectRequestSchema = zod_1.z.object({
    orderRef: zod_1.z.string(),
});
//
// Type definitions for /cancel
//
exports.cancelSchema = zod_1.z.object({
    orderRef: zod_1.z.string(),
});
var BankIdErrorCode;
(function (BankIdErrorCode) {
    BankIdErrorCode["ALREADY_IN_PROGRESS"] = "alreadyInProgress";
    BankIdErrorCode["INVALID_PARAMETERS"] = "invalidParameters";
    BankIdErrorCode["UNAUTHORIZED"] = "unauthorized";
    BankIdErrorCode["NOT_FOUND"] = "notFound";
    BankIdErrorCode["METHOD_NOT_ALLOWED"] = "methodNotAllowed";
    BankIdErrorCode["REQUEST_TIMEOUT"] = "requestTimeout";
    BankIdErrorCode["UNSUPPORTED_MEDIA_TYPE"] = "unsupportedMediaType";
    BankIdErrorCode["INTERNAL_ERROR"] = "internalError";
    BankIdErrorCode["MAINTENANCE"] = "maintenance";
})(BankIdErrorCode || (exports.BankIdErrorCode = BankIdErrorCode = {}));
exports.REQUEST_FAILED_ERROR = "BANKID_NO_RESPONSE";
//
// Collection of overarching types
//
var BankIdMethod;
(function (BankIdMethod) {
    BankIdMethod["auth"] = "auth";
    BankIdMethod["sign"] = "sign";
    BankIdMethod["collect"] = "collect";
    BankIdMethod["cancel"] = "cancel";
})(BankIdMethod || (exports.BankIdMethod = BankIdMethod = {}));
//
// Error types
//
class BankIdError extends Error {
    constructor(code, details) {
        super(code);
        Error.captureStackTrace(this, this.constructor);
        this.name = "BankIdError";
        this.code = code;
        this.details = details;
    }
}
exports.BankIdError = BankIdError;
class RequestError extends Error {
    constructor(request) {
        super(exports.REQUEST_FAILED_ERROR);
        Error.captureStackTrace(this, this.constructor);
        this.name = "RequestError";
        this.request = request;
    }
}
exports.RequestError = RequestError;
//
// Client implementation
//
class BankIdClient {
    constructor(options) {
        this.options = Object.assign({ production: false, refreshInterval: 2000 }, options);
        if (this.options.production) {
            if (!(options === null || options === void 0 ? void 0 : options.pfx) || !(options === null || options === void 0 ? void 0 : options.passphrase)) {
                throw new Error("BankId requires the pfx and passphrase in production mode");
            }
        }
        else {
            // Provide default PFX & passphrase in test
            if (this.options.pfx === undefined) {
                this.options.pfx = path.resolve(__dirname, "../cert/", "FPTestcert4_20220818.p12");
            }
            if (this.options.passphrase === undefined) {
                this.options.passphrase = "qwerty123";
            }
        }
        // Provide certificate by default
        if (this.options.ca === undefined) {
            this.options.ca = this.options.production
                ? path.resolve(__dirname, "../cert/", "prod.ca")
                : path.resolve(__dirname, "../cert/", "test.ca");
        }
        this.axios = this._createAxiosInstance();
        this.baseUrl = this.options.production
            ? "https://appapi2.bankid.com/rp/v6.0/"
            : "https://appapi2.test.bankid.com/rp/v6.0/";
    }
    authenticate(parameters) {
        const validatedParameters = exports.authRequestSchema.parse(parameters);
        return this._call(BankIdMethod.auth, validatedParameters);
    }
    sign(parameters) {
        const validatedParameters = exports.signRequestSchema.parse(parameters);
        return this._call(BankIdMethod.sign, validatedParameters);
    }
    collect(parameters) {
        const validatedParameters = collectRequestSchema.parse(parameters);
        return this._call(BankIdMethod.collect, validatedParameters);
    }
    cancel(parameters) {
        return this._call(BankIdMethod.cancel, parameters);
    }
    authenticateAndCollect(parameters, handleAuthResponse, handleCollectResponse) {
        return __awaiter(this, void 0, void 0, function* () {
            console.log("authenticateAndCollect");
            const authResponse = yield this.authenticate(parameters);
            console.log("authResponse", authResponse);
            yield handleAuthResponse(authResponse);
            return this._awaitPendingCollect(authResponse.orderRef, handleCollectResponse);
        });
    }
    signAndCollect(parameters, handleSignResponse, handleCollectResponse) {
        return __awaiter(this, void 0, void 0, function* () {
            console.log("signAndCollect");
            const signResponse = yield this.sign(parameters);
            yield handleSignResponse(signResponse);
            return this._awaitPendingCollect(signResponse.orderRef, handleCollectResponse);
        });
    }
    _awaitPendingCollect(orderRef, handleCollectResponse) {
        console.log("awaitPendingCollect");
        const randomNumber = Math.floor(Math.random() * 1000000);
        let cancel = false;
        const timer = setInterval(() => __awaiter(this, void 0, void 0, function* () {
            console.log("timer", randomNumber);
            try {
                const response = yield this.collect({ orderRef });
                if (cancel) {
                    return;
                }
                if (response.status === "complete") {
                    clearInterval(timer);
                    handleCollectResponse(response);
                }
                else if (response.status === "failed") {
                    clearInterval(timer);
                    handleCollectResponse(response);
                }
                handleCollectResponse(response);
            }
            catch (error) {
                clearInterval(timer);
                throw error;
            }
        }), this.options.refreshInterval);
        console.log("timer", timer);
        return () => {
            console.log("clearInterval", timer);
            clearInterval(timer);
            cancel = true;
        };
    }
    _call(method, payload) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const response = yield this.axios.post(this.baseUrl + method, payload);
                return response.data;
            }
            catch (error) {
                let thrownError = error;
                if (axios_1.default.isAxiosError(error)) {
                    if (error.response) {
                        thrownError = new BankIdError(error.response.data.errorCode, error.response.data.details);
                    }
                    else if (error.request) {
                        thrownError = new RequestError(error.request);
                    }
                }
                throw thrownError;
            }
        });
    }
    _createAxiosInstance() {
        const ca = Buffer.isBuffer(this.options.ca)
            ? this.options.ca
            : fs.readFileSync(this.options.ca, "utf-8");
        const pfx = Buffer.isBuffer(this.options.pfx)
            ? this.options.pfx
            : fs.readFileSync(this.options.pfx);
        const passphrase = this.options.passphrase;
        return axios_1.default.create({
            httpsAgent: new https.Agent({ pfx, passphrase, ca }),
            headers: {
                "Content-Type": "application/json",
            },
        });
    }
}
exports.BankIdClient = BankIdClient;
