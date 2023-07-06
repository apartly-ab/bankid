import * as fs from "fs";
import * as https from "https";
import * as path from "path";

import type { AxiosInstance } from "axios";
import axios from "axios";
import { z } from "zod";
import { EventEmitter } from "stream";

//
// Type definitions for /auth
//

const authOptionalRequirementsSchema = z.object({
    pinCode: z.boolean().optional(),
    mrtd: z.boolean().optional(),
    cardReader: z.literal("class1").or(z.literal("class2")).optional(),
    certificatePolicies: z.array(z.string()).optional(),
    personalNumber: z.string().optional(),
}).optional();

const userVisibleDataSchema = z.string().refine((s) => {
    try {
        const correctSize = Buffer.from(s, "base64").length <= 40000;
        const correctEncoding = Buffer.from(s, "base64").toString("base64") === s;
        return correctSize && correctEncoding;
    } catch (e) {
        return false;
    }
}, "userVisibleData must be base64 encoded, 1-40000 characters in its base64 encoded state")
const userNonVisibleDataSchema = z.string().refine((s) => {
    try {
        return Buffer.from(s, "base64").length <= 200000;
    } catch (e) {
        return false;
    }
}, "userVisibleData must be base64 encoded, 1-200000 characters in its base64 encoded state")


export const authRequestSchema = z.object({
    endUserIp: z.string(),
    personalNumber: z.string().optional(),
    requirement: authOptionalRequirementsSchema,
    //userVisibleData, if present, must be encoded as UTF-8 and then base 64 encoded. 1 – 40,000 characters after base 64 encoding
    userVisibleData: userVisibleDataSchema.optional(),
    //userNonVisibleData, if present, must be base64 encoded, 1-200000 characters in its base64 encoded state
    userNonVisibleData: userNonVisibleDataSchema.optional(),
    userVisibleDataFormat: z.literal("simpleMarkdownV1").optional(),
});

export const phoneAuthSchema = authRequestSchema.extend({
    personalNumber: z.string(),
    callInitiator: z.literal("user").or(z.literal("RP"))
});

export type PhoneAuthRequest = z.infer<typeof phoneAuthSchema>;

export interface PhoneAuthResponse {
    orderRef: string;
}

export const signRequestSchema = authRequestSchema.extend({
    userVisibleData: userVisibleDataSchema,
});

export type AuthRequest = z.infer<typeof authRequestSchema>;

export interface AuthResponse {
  autoStartToken: string;
  qrStartSecret: string;
  qrStartToken: string;
  orderRef: string;
}


type AuthOptionalRequirements = z.infer<typeof authOptionalRequirementsSchema>;

//
// Type definitions for /sign
//

export type SignRequest = z.infer<typeof signRequestSchema>;

export interface SignResponse extends AuthResponse {}

//
// Type definitions for /collect
//

const collectRequestSchema = z.object({
    orderRef: z.string(),
});

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

export type FailedHintCode =
  | "expiredTransaction"
  | "certificateErr"
  | "userCancel"
  | "cancelled"
  | "startFailed";

export type PendingHintCode =
  | "outstandingTransaction"
  | "noClient"
  | "started"
  | "userMrtd"
  | "userCallConfirm"
  | "userSign"


//
// Type definitions for /cancel
//

export const cancelSchema = z.object({
    orderRef: z.string(),
});

export type CancelRequest = z.infer<typeof cancelSchema>;

export interface CancelResponse {
}

//
// Type definitions for error responses
//

export interface ErrorResponse {
  errorCode: BankIdErrorCode;
  details: string;
}

export enum BankIdErrorCode {
  ALREADY_IN_PROGRESS = "alreadyInProgress",
  INVALID_PARAMETERS = "invalidParameters",
  UNAUTHORIZED = "unauthorized",
  NOT_FOUND = "notFound",
  METHOD_NOT_ALLOWED = "methodNotAllowed",
  REQUEST_TIMEOUT = "requestTimeout",
  UNSUPPORTED_MEDIA_TYPE = "unsupportedMediaType",
  INTERNAL_ERROR = "internalError",
  MAINTENANCE = "maintenance",
}

export const REQUEST_FAILED_ERROR = "BANKID_NO_RESPONSE";

//
// Collection of overarching types
//

export enum BankIdMethod {
  auth = "auth",
  sign = "sign",
  collect = "collect",
  cancel = "cancel",
}

export type BankIdRequest =
  | AuthRequest
  | SignRequest
  | CollectRequest
  | CancelRequest;

export type BankIdResponse =
  | CancelResponse
  | AuthResponse
  | SignResponse
  | CollectResponse;

//
// Client settings
//

export interface BankIdClientSettings {
  production: boolean;
  refreshInterval?: number;
  pfx?: string | Buffer;
  passphrase?: string;
  ca?: string | Buffer;
}

//
// Error types
//

export class BankIdError extends Error {
  readonly code: BankIdErrorCode;
  readonly details?: string;

  constructor(code: BankIdErrorCode, details?: string) {
    super(code);
    Error.captureStackTrace(this, this.constructor);

    this.name = "BankIdError";
    this.code = code;
    this.details = details;
  }
}

export type collectResponseHandler = (
    response: CollectResponse,
    ) => Promise<void>;

export type authResponseHandler = (
    response: AuthResponse,
    ) => Promise<void>;

export type signResponseHandler = (
    response: SignResponse,
    ) => Promise<void>;

export class RequestError extends Error {
  readonly request?: any;

  constructor(request?: any) {
    super(REQUEST_FAILED_ERROR);
    Error.captureStackTrace(this, this.constructor);

    this.name = "RequestError";
    this.request = request;
  }
}

interface CoreAuthEvents {
  "collect:pending": (response: CollectResponse) => void;
  "collect:failed": (response: CollectResponse) => void;
  "collect:complete": (response: CollectResponse) => void;
  "auth:start": (response: AuthResponse) => void;
  "sign:start": (response: SignResponse) => void;
}

//
// Client implementation -- Reusable.
//

export class BankIdClient extends EventEmitter {
  readonly options: Required<BankIdClientSettings>;
  readonly axios: AxiosInstance;
  readonly baseUrl: string;

  constructor(options?: BankIdClientSettings) {
    super()
    this.options = {
      production: false,
      refreshInterval: 2000,
      ...options,
    } as Required<BankIdClientSettings>;

    if (this.options.production) {
      if (!options?.pfx || !options?.passphrase) {
        throw new Error(
          "BankId requires the pfx and passphrase in production mode",
        );
      }
    } else {
      // Provide default PFX & passphrase in test
      if (this.options.pfx === undefined) {
        this.options.pfx = path.resolve(
          __dirname,
          "../cert/",
          "FPTestcert4_20220818.p12",
        );
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

  on<U extends keyof CoreAuthEvents>(
    event: U, listener: CoreAuthEvents[U]): this {
        super.on(event, listener);
        return this;
    }

  emit<U extends keyof CoreAuthEvents>(
    event: U, ...args: Parameters<CoreAuthEvents[U]>): boolean {
        return super.emit(event, ...args);
    }

  authenticate(parameters: AuthRequest): Promise<AuthResponse> {
    const validatedParameters = authRequestSchema.parse(parameters);
    return this._call<AuthRequest, AuthResponse>(BankIdMethod.auth, validatedParameters);
  }

  sign(parameters: SignRequest): Promise<SignResponse> {
    const validatedParameters = signRequestSchema.parse(parameters);
    return this._call<SignRequest, SignResponse>(BankIdMethod.sign, validatedParameters);
  }

  collect(parameters: CollectRequest) {
    const validatedParameters = collectRequestSchema.parse(parameters);
    return this._call<CollectRequest, CollectResponse>(
      BankIdMethod.collect,
      validatedParameters,
    );
  }

  cancel(parameters: CollectRequest): Promise<CancelResponse> {
    return this._call<CollectRequest, CancelResponse>(
      BankIdMethod.cancel,
      parameters,
    );
  }

  /**
   * Authenticate and collect
   * 
   * Initializes an authentication order with BankID and periodically collects the status of the order until it is complete or failed.
   * It will also renew the authentication order if it expires and the maxEndTime has not been reached.
   * 
   * Whenever a collect call returns, the client will emit an event with the response.
   * 
   * @param parameters The parameters for the authentication request. [Read more](https://www.bankid.com/en/utvecklare/guider/teknisk-integrationsguide/graenssnittsbeskrivning/auth)
   */
  async authenticateAndCollect(
    parameters: AuthRequest,
  ) {
    const authResponse = await this.authenticate(parameters);
    this.emit("auth:start", authResponse);
    return this._awaitPendingCollect(authResponse.orderRef);
  }

  /**
   * Sign and collect
   * 
   * Initializes a signing order with BankID and periodically collects the status of the order until it is complete or failed.
   * It will also renew the signing order if it expires and the maxEndTime has not been reached.
   * 
   * Whenever a collect call returns, the client will emit an event with the response.
   * 
   * @param parameters The parameters for the signing request. [Read more](https://www.bankid.com/en/utvecklare/guider/teknisk-integrationsguide/graenssnittsbeskrivning/sign)
   */
  async signAndCollect(
    parameters: SignRequest,
    ) {
    const signResponse = await this.sign(parameters);
    this.emit("sign:start", signResponse);
    return this._awaitPendingCollect(signResponse.orderRef);
  }


  _awaitPendingCollect(orderRef: string) {
    console.log("awaitPendingCollect");
    const randomNumber = Math.floor(Math.random() * 1000000);
    let cancel = false;
    const timer = setInterval(async () => {
        console.log("timer", randomNumber)
        try {
            if(cancel) {
                return;
            }
            const response = await this.collect({ orderRef })
            console.log(randomNumber, response.hintCode)
            if (response.status === "complete") {
                clearInterval(timer);
                console.log("killed timer", randomNumber)
                this.emit("collect:complete", response);
              } else if (response.status === "failed") {
                clearInterval(timer);
                console.log("killed timer", randomNumber)
                this.emit("collect:failed", response);
              }
            this.emit("collect:pending", response);
        } catch (error) {
            clearInterval(timer);
            console.log("killed timer", randomNumber)
            super.emit("collect:failed", error);
        }
    }, this.options.refreshInterval);
    return () => {
      clearInterval(timer)
      console.log("killed timer", randomNumber)
      cancel = true;
    };
  }

  /**
   * Helper method to finalize an authentication order. Only call when you expect that the order is complete.
   **/
  async finalCollect(orderRef: string) : Promise<CollectResponse> {
    const response = await this.collect({ orderRef });
    if (response.status === "complete") {
      this.emit("collect:complete", response);
    } else {
      this.emit("collect:failed", response);
    }
    return response;
  }
  

  async _call<Req extends BankIdRequest, Res extends BankIdResponse>(
    method: BankIdMethod,
    payload: Req,
  ): Promise<Res> {
    try{
        const response = await this.axios.post<Res>(this.baseUrl + method, payload);
        return response.data;
    } catch (error) {
        let thrownError = error;
        if (axios.isAxiosError(error)) {
            if (error.response) {
                thrownError = new BankIdError(
                    error.response.data.errorCode,
                    error.response.data.details,
                );
            } else if (error.request) {
                thrownError = new RequestError(error.request);
            }
        }
        throw thrownError;
    }
    }

  _createAxiosInstance(): AxiosInstance {
    const ca = Buffer.isBuffer(this.options.ca)
      ? this.options.ca
      : fs.readFileSync(this.options.ca, "utf-8");
    const pfx = Buffer.isBuffer(this.options.pfx)
      ? this.options.pfx
      : fs.readFileSync(this.options.pfx);
    const passphrase = this.options.passphrase;

    return axios.create({
      httpsAgent: new https.Agent({ pfx, passphrase, ca }),
      headers: {
        "Content-Type": "application/json",
      },
    });
  }
}

export type BankIdDevice = "sameMobile" | "otherMobile" | "sameDesktop";



const querySchema = z.object({
  action: z.enum(['authenticate', 'sign', 'finalize']),
  bankIdDevice: z.enum(['sameMobile', 'otherMobile', 'sameDesktop']),
  time: z.number(),
  signature: z.string(),
});

/**
export const handler = streamifyResponse(async (event: APIGatewayProxyEventV2, responseStream : ResponseStream, context: APIGatewayEventRequestContextV2) => {
  try {
      const {action, bankIdDevice, time, signature} = querySchema.parse(event.queryStringParameters || {});
      const hmacKey = process.env.AUTH_HMAC_KEY as string;
      if(!hmacKey) throw new Error("No HMAC key provided");
      const hmac = createHmac('sha256', hmacKey).update(`${action}${bankIdDevice}${time}`).digest('hex');
      if(hmac !== signature){
          responseStream.write(new SSFailureEvent({reason: "Invalid signature"}));
          responseStream.end();
          return;
      }
      const bankIdHandler = new BankIdHandler(bankid, responseStream, bankIdDevice);
  
      // Set content type, because EventSource requires it to be text/event-stream
      responseStream.setContentType('text/event-stream');
      if(!action) throw new Error("No action provided");
  
      if(action === 'authenticate'){
          const endUserIp = event.headers['x-forwarded-for']?.replace("::ffff:", "") || event.requestContext.http.sourceIp;
          const authRequest: AuthRequest = {
              endUserIp,
          }
          await bankIdHandler.authenticateAndCollect(authRequest).catch(err => console.log("Error", err, event));
      } else {
          responseStream.write(new SSFailureEvent({reason: "Invalid action"}));
          responseStream.end();
      }
  } catch(err){
      console.log("Error", err, event);
      responseStream.write(new SSFailureEvent({reason: "Invalid request"}));
      responseStream.end();
  }
}
)
*/
