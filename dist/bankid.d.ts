/// <reference types="node" />
import type { AxiosInstance } from "axios";
import { z } from "zod";
export declare const authRequestSchema: z.ZodObject<{
    endUserIp: z.ZodString;
    personalNumber: z.ZodOptional<z.ZodString>;
    requirement: z.ZodOptional<z.ZodObject<{
        pinCode: z.ZodOptional<z.ZodBoolean>;
        mrtd: z.ZodOptional<z.ZodBoolean>;
        cardReader: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<"class1">, z.ZodLiteral<"class2">]>>;
        certificatePolicies: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        personalNumber: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    }, {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    }>>;
    userVisibleData: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    userNonVisibleData: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    userVisibleDataFormat: z.ZodOptional<z.ZodLiteral<"simpleMarkdownV1">>;
}, "strip", z.ZodTypeAny, {
    endUserIp: string;
    personalNumber?: string | undefined;
    requirement?: {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    } | undefined;
    userVisibleData?: string | undefined;
    userNonVisibleData?: string | undefined;
    userVisibleDataFormat?: "simpleMarkdownV1" | undefined;
}, {
    endUserIp: string;
    personalNumber?: string | undefined;
    requirement?: {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    } | undefined;
    userVisibleData?: string | undefined;
    userNonVisibleData?: string | undefined;
    userVisibleDataFormat?: "simpleMarkdownV1" | undefined;
}>;
export declare const phoneAuthSchema: z.ZodObject<{
    endUserIp: z.ZodString;
    requirement: z.ZodOptional<z.ZodObject<{
        pinCode: z.ZodOptional<z.ZodBoolean>;
        mrtd: z.ZodOptional<z.ZodBoolean>;
        cardReader: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<"class1">, z.ZodLiteral<"class2">]>>;
        certificatePolicies: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        personalNumber: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    }, {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    }>>;
    userVisibleData: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    userNonVisibleData: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    userVisibleDataFormat: z.ZodOptional<z.ZodLiteral<"simpleMarkdownV1">>;
    personalNumber: z.ZodString;
    callInitiator: z.ZodUnion<[z.ZodLiteral<"user">, z.ZodLiteral<"RP">]>;
}, "strip", z.ZodTypeAny, {
    personalNumber: string;
    endUserIp: string;
    callInitiator: "user" | "RP";
    requirement?: {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    } | undefined;
    userVisibleData?: string | undefined;
    userNonVisibleData?: string | undefined;
    userVisibleDataFormat?: "simpleMarkdownV1" | undefined;
}, {
    personalNumber: string;
    endUserIp: string;
    callInitiator: "user" | "RP";
    requirement?: {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    } | undefined;
    userVisibleData?: string | undefined;
    userNonVisibleData?: string | undefined;
    userVisibleDataFormat?: "simpleMarkdownV1" | undefined;
}>;
export type PhoneAuthRequest = z.infer<typeof phoneAuthSchema>;
export interface PhoneAuthResponse {
    orderRef: string;
}
export declare const signRequestSchema: z.ZodObject<{
    personalNumber: z.ZodOptional<z.ZodString>;
    endUserIp: z.ZodString;
    requirement: z.ZodOptional<z.ZodObject<{
        pinCode: z.ZodOptional<z.ZodBoolean>;
        mrtd: z.ZodOptional<z.ZodBoolean>;
        cardReader: z.ZodOptional<z.ZodUnion<[z.ZodLiteral<"class1">, z.ZodLiteral<"class2">]>>;
        certificatePolicies: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        personalNumber: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    }, {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    }>>;
    userNonVisibleData: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    userVisibleDataFormat: z.ZodOptional<z.ZodLiteral<"simpleMarkdownV1">>;
    userVisibleData: z.ZodEffects<z.ZodString, string, string>;
}, "strip", z.ZodTypeAny, {
    endUserIp: string;
    userVisibleData: string;
    personalNumber?: string | undefined;
    requirement?: {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    } | undefined;
    userNonVisibleData?: string | undefined;
    userVisibleDataFormat?: "simpleMarkdownV1" | undefined;
}, {
    endUserIp: string;
    userVisibleData: string;
    personalNumber?: string | undefined;
    requirement?: {
        pinCode?: boolean | undefined;
        mrtd?: boolean | undefined;
        cardReader?: "class1" | "class2" | undefined;
        certificatePolicies?: string[] | undefined;
        personalNumber?: string | undefined;
    } | undefined;
    userNonVisibleData?: string | undefined;
    userVisibleDataFormat?: "simpleMarkdownV1" | undefined;
}>;
export type AuthRequest = z.infer<typeof authRequestSchema>;
export interface AuthResponse {
    autoStartToken: string;
    qrStartSecret: string;
    qrStartToken: string;
    orderRef: string;
}
export type SignRequest = z.infer<typeof signRequestSchema>;
export interface SignResponse extends AuthResponse {
}
declare const collectRequestSchema: z.ZodObject<{
    orderRef: z.ZodString;
}, "strip", z.ZodTypeAny, {
    orderRef: string;
}, {
    orderRef: string;
}>;
export type CollectRequest = z.infer<typeof collectRequestSchema>;
export interface CollectResponse {
    orderRef: string;
    status: "pending" | "failed" | "complete";
    hintCode?: FailedHintCode | PendingHintCode;
    completionData?: CompletionData;
}
export interface CompletionData {
    user: {
        personalNumber: string;
        name: string;
        givenName: string;
        surname: string;
    };
    device: {
        ipAddress: string;
        uhi: string;
    };
    bankIdIssueDate: string;
    stepUp: boolean;
    cert: {
        notBefore: string;
        notAfter: string;
    };
    signature: string;
    ocspResponse: string;
}
export type FailedHintCode = "expiredTransaction" | "certificateErr" | "userCancel" | "cancelled" | "startFailed";
export type PendingHintCode = "outstandingTransaction" | "noClient" | "started" | "userMrtd" | "userCallConfirm" | "userSign";
export declare const cancelSchema: z.ZodObject<{
    orderRef: z.ZodString;
}, "strip", z.ZodTypeAny, {
    orderRef: string;
}, {
    orderRef: string;
}>;
export type CancelRequest = z.infer<typeof cancelSchema>;
export interface CancelResponse {
}
export interface ErrorResponse {
    errorCode: BankIdErrorCode;
    details: string;
}
export declare enum BankIdErrorCode {
    ALREADY_IN_PROGRESS = "alreadyInProgress",
    INVALID_PARAMETERS = "invalidParameters",
    UNAUTHORIZED = "unauthorized",
    NOT_FOUND = "notFound",
    METHOD_NOT_ALLOWED = "methodNotAllowed",
    REQUEST_TIMEOUT = "requestTimeout",
    UNSUPPORTED_MEDIA_TYPE = "unsupportedMediaType",
    INTERNAL_ERROR = "internalError",
    MAINTENANCE = "maintenance"
}
export declare const REQUEST_FAILED_ERROR = "BANKID_NO_RESPONSE";
export declare enum BankIdMethod {
    auth = "auth",
    sign = "sign",
    collect = "collect",
    cancel = "cancel"
}
export type BankIdRequest = AuthRequest | SignRequest | CollectRequest | CancelRequest;
export type BankIdResponse = CancelResponse | AuthResponse | SignResponse | CollectResponse;
export interface BankIdClientSettings {
    production: boolean;
    refreshInterval?: number;
    pfx?: string | Buffer;
    passphrase?: string;
    ca?: string | Buffer;
}
export declare class BankIdError extends Error {
    readonly code: BankIdErrorCode;
    readonly details?: string;
    constructor(code: BankIdErrorCode, details?: string);
}
export type collectResponseHandler = (response: CollectResponse) => Promise<void>;
export type authResponseHandler = (response: AuthResponse) => Promise<void>;
export type signResponseHandler = (response: SignResponse) => Promise<void>;
export declare class RequestError extends Error {
    readonly request?: any;
    constructor(request?: any);
}
export declare class BankIdClient {
    readonly options: Required<BankIdClientSettings>;
    readonly axios: AxiosInstance;
    readonly baseUrl: string;
    constructor(options?: BankIdClientSettings);
    authenticate(parameters: AuthRequest): Promise<AuthResponse>;
    sign(parameters: SignRequest): Promise<SignResponse>;
    collect(parameters: CollectRequest): Promise<CollectResponse>;
    cancel(parameters: CollectRequest): Promise<CancelResponse>;
    authenticateAndCollect(parameters: AuthRequest, handleAuthResponse: authResponseHandler, handleCollectResponse: collectResponseHandler): Promise<() => void>;
    signAndCollect(parameters: SignRequest, handleSignResponse: signResponseHandler, handleCollectResponse: collectResponseHandler): Promise<() => void>;
    _awaitPendingCollect(orderRef: string, handleCollectResponse: collectResponseHandler): () => void;
    _call<Req extends BankIdRequest, Res extends BankIdResponse>(method: BankIdMethod, payload: Req): Promise<Res>;
    _createAxiosInstance(): AxiosInstance;
}
export {};
