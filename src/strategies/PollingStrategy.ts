import { createCipheriv, createDecipheriv, createHmac, randomBytes,  } from "crypto";
import { AuthenticationClient, BankIdClient } from "..";
import { AuthResponse, SignResponse, CollectResponse, AuthRequest, SignRequest, CollectRequest, BankIdDevice } from "../bankid";

export interface IPollingStrategyProps<SuccessType>{
    options?: {
        pollInterval?: number,
        maxPollAge?: number,
        maxRetries?: number,
    },
    orderRefHashKey: string,
    authClient: AuthenticationClient<SuccessType>,
    bankid: BankIdClient,
    device: BankIdDevice,
    qrStartSecretEncryptionKey: string,
}

export interface IPollResponse {
    orderRef: string,
    hintCode: CollectResponse['hintCode'],
    qrCode: string,
    retriesLeft: number,
    startTime: number,
    qrStartToken: string,
    autoStartToken?: string,
    nextPollTime: number,
    junk: string,
}

export interface ISuccessResponse<SuccessType> extends IPollResponse {
    tokens: SuccessType,
}

export interface IPollRequest {
    orderRef: string,
    nextPollTime: number,
    junk: string,
    startTime: number,
    qrStartToken: string,
    retriesLeft: number,
    ipAddress: string,
}

interface IVerifiedJunk {
    junk: string,
    startTime: number,
    retriesLeft: number,
    nextPollTime: number,
    qrStartToken: string,
    qrStartSecret: string,
    encryptedQrStartSecret: string,
    orderRef: string,
    ivString: string,
}


export default class PollingStrategy<SuccessType> {
    private pollInterval: number;
    // The maximum amount of time a user is allowed to wait before polling with their signed orderRef
    private maxPollAge: number;
    private maxRetries: number;
    private orderRefHashKey: string;
    private qrStartSecretEncryptionKey: string;
    private authClient: AuthenticationClient<SuccessType>;
    protected bankid: BankIdClient;
    protected bankIdDevice: BankIdDevice;

    protected handleSignResponse(response: SignResponse): void {
        throw new Error("Method not implemented.");
    }
    protected cancelOrder(): void {
        throw new Error("Method not implemented.");
    }

    constructor({ options, authClient, bankid, device, orderRefHashKey, qrStartSecretEncryptionKey }: IPollingStrategyProps<SuccessType>) {
        this.pollInterval = options && options.pollInterval || 1000;
        this.maxPollAge = options && options.maxPollAge || 1000 * 5;
        this.maxRetries = options && options.maxRetries || 3;
        this.bankid = bankid;
        this.orderRefHashKey = orderRefHashKey;
        this.bankIdDevice = device;
        this.authClient = authClient;
        this.qrStartSecretEncryptionKey = qrStartSecretEncryptionKey;
    }

    /**Create a response from a collect response and an optional auth or sign response
     * This method generates a response that can be sent to the client. It includes information about the status of the order, and a qr code if the order is pending. 
     * Importantly, it contains a hash of the orderRef and the next poll time. This allows us to remain stateless on the server, and still be able to verify that each poll request is valid. We only hash the orderRef and next poll time, because this gives us something akin to a contract that says: "The holder of this string is allowed to poll for this orderRef at this time". If we hashed the entire response, the user would have to send that response back to us, which should not be necessary.
     */
    private createResponse({
        retriesLeft, 
        collectResponse, 
        authResponse, 
        signResponse, 
        verifiedJunk,
    } : {
        collectResponse: CollectResponse,
        authResponse?: AuthResponse,
        signResponse?: SignResponse,
        retriesLeft: number,
        verifiedJunk?: IVerifiedJunk,
    }): IPollResponse {
        if(authResponse){
            return this.createAuthResponse({
                authResponse,
                collectResponse,
                retriesLeft,
            })
        }
        else if(signResponse){
            return this.createSignResponse({
                signResponse,
                collectResponse,
                retriesLeft,
            })
        }
        else {
            if(!verifiedJunk){
                throw new Error("No junk provided")
            }
            return this.createCollectResponse({
                collectResponse,
                retriesLeft,
                verifiedJunk,
            })
        }
}

    private createAuthResponse({
        authResponse,
        collectResponse,
        retriesLeft
    }: {
        authResponse: AuthResponse,
        collectResponse: CollectResponse,
        retriesLeft: number,
    }): IPollResponse {
        const junkableObject = {
            nextPollTime: Date.now() + (this.pollInterval || 1000),
            orderRef: authResponse.orderRef,
            startTime: Date.now(),
            retriesLeft,
            qrStartToken: authResponse.qrStartToken,
            qrStartSecret: authResponse.qrStartSecret,
            qrStartSecretEncryptionKey: this.qrStartSecretEncryptionKey,
        }
        const junk = this.createJunk(junkableObject);
        return {
            orderRef: authResponse.orderRef,
            hintCode: collectResponse.hintCode,
            qrCode: this.createQrCode({
                qrStartSecret: authResponse.qrStartSecret,
                qrStartToken: authResponse.qrStartToken,
                response: collectResponse,
                startTime: Date.now(),
            }),
            retriesLeft,
            startTime: Date.now(),
            qrStartToken: authResponse.qrStartToken,
            nextPollTime: Date.now() + (this.pollInterval || 1000),
            junk
        }
    }

    private createSignResponse({
        signResponse,
        collectResponse,
        retriesLeft
    }: {
        signResponse: SignResponse,
        collectResponse: CollectResponse,
        retriesLeft: number,
    }): IPollResponse {
        const junkableObject = {
            nextPollTime: Date.now() + (this.pollInterval || 1000),
            orderRef: signResponse.orderRef,
            startTime: Date.now(),
            retriesLeft,
            qrStartToken: signResponse.qrStartToken,
            qrStartSecret: signResponse.qrStartSecret,
            qrStartSecretEncryptionKey: this.qrStartSecretEncryptionKey,
        }
        const junk = this.createJunk(junkableObject);
        return {
            orderRef: signResponse.orderRef,
            hintCode: collectResponse.hintCode,
            qrCode: this.createQrCode({
                qrStartSecret: signResponse.qrStartSecret,
                qrStartToken: signResponse.qrStartToken,
                response: collectResponse,
                startTime: Date.now(),
            }),
            retriesLeft,
            startTime: Date.now(),
            qrStartToken: signResponse.qrStartToken,
            nextPollTime: Date.now() + (this.pollInterval || 1000),
            junk
        }
    }

    private createCollectResponse({
        collectResponse,
        retriesLeft,
        verifiedJunk,
    }: {
        collectResponse: CollectResponse,
        retriesLeft: number,
        verifiedJunk: IVerifiedJunk,
    }): IPollResponse {
        const { startTime, qrStartToken, qrStartSecret } = verifiedJunk;
        const junkableObject = {
            nextPollTime: Date.now() + (this.pollInterval || 1000),
            orderRef: collectResponse.orderRef,
            startTime,
            retriesLeft,
            qrStartToken,
            qrStartSecret,
            qrStartSecretEncryptionKey: this.qrStartSecretEncryptionKey,
        }
        const junk = this.createJunk(junkableObject);
        return {
            orderRef: collectResponse.orderRef,
            hintCode: collectResponse.hintCode,
            qrCode: this.createQrCode({
                qrStartSecret,
                qrStartToken,
                response: collectResponse,
                startTime,
            }),
            retriesLeft,
            startTime,
            qrStartToken,
            nextPollTime: Date.now() + (this.pollInterval || 1000),
            junk
        }
    }

    private async createCompleteResponse({
        collectResponse,
        verifiedJunk,
    }: {
        collectResponse: CollectResponse,
        verifiedJunk: IVerifiedJunk,
    }): Promise<ISuccessResponse<SuccessType>> {
        const completionData = collectResponse.completionData;
        if(!completionData){
            throw new Error("No completion data provided");
        }
        const tokens = await this.authClient.run(completionData);
        const { startTime, qrStartToken, qrStartSecret } = verifiedJunk;
        return {
            orderRef: "DONE",
            hintCode: collectResponse.hintCode,
            retriesLeft: 0,
            qrCode: "",
            startTime,
            qrStartToken,
            nextPollTime: Number.MAX_SAFE_INTEGER,
            junk: "",
            tokens,
        }
    }
        

    /**
     * Do not be fooled by its name. This method creates an encrypted, hmacced string that contains the qrStartSecret, which must be kept secret from the client.
     * By sending this to the client, we can allow a fully stateless system, where the client is responsible for proving their right to collect the status of the order. Really, this is a hacked together version of a JWT with an encrypted payload.
     */
    private createJunk({
        nextPollTime,
        orderRef,
        retriesLeft,
        encryptedQrStartSecret,
        startTime,
        ivString,
        qrStartToken,
        qrStartSecret,
        qrStartSecretEncryptionKey,
    }: {
        nextPollTime: number,
        orderRef: string,
        encryptedQrStartSecret?: string,
        startTime: number,
        ivString?: string,
        retriesLeft: number,
        qrStartToken?: string,
        qrStartSecret?: string,
        qrStartSecretEncryptionKey: string,
    }){
        let encrypted = encryptedQrStartSecret || '';
        if(!encryptedQrStartSecret){
            if(!qrStartSecret) throw new Error("No qrStartSecret provided");
            const iv = randomBytes(16);
            ivString = iv.toString('hex');
            const cipher = createCipheriv('aes-256-gcm', qrStartSecretEncryptionKey, iv);
            encrypted += cipher.update(qrStartSecret, 'utf8', 'hex');
            encrypted += cipher.final('hex');
        }
        const junkableItems = {
            encryptedQrStartSecret,
            ivString,
            nextPollTime,
            orderRef,
            qrStartToken,
            retriesLeft,
            startTime,
        }
        const junkableString = `${junkableItems.encryptedQrStartSecret}${junkableItems.ivString}${junkableItems.nextPollTime}${junkableItems.orderRef}${junkableItems.qrStartToken}${junkableItems.retriesLeft}${junkableItems.startTime}`;
        const hash = createHmac('sha256', this.orderRefHashKey).update(junkableString).digest('hex');
        const junk = `${ivString}.${encrypted}.${hash}`
        return junk;
    }

    private verifyJunk(order: IPollRequest){
        const junk = order.junk.split('.');
        if(junk.length !== 3) throw new Error("Invalid junk");
        const [ivString, encryptedQrStartSecret, hash] = junk;
        const junkableItems = {
            encryptedQrStartSecret,
            ivString,
            nextPollTime: order.nextPollTime,
            orderRef: order.orderRef,
            qrStartToken: order.qrStartToken,
            retriesLeft: order.retriesLeft,
            startTime: order.startTime,
        }
        const junkableString = `${junkableItems.encryptedQrStartSecret}${junkableItems.ivString}${junkableItems.nextPollTime}${junkableItems.orderRef}${junkableItems.qrStartToken}${junkableItems.retriesLeft}${junkableItems.startTime}`;
        const calculatedHash = createHmac('sha256', this.orderRefHashKey).update(junkableString).digest('hex');
        if(calculatedHash !== hash) throw new Error("Invalid junk");
        // Decrypt the qrStartSecret
        const decipher = createDecipheriv('aes-256-gcm', this.qrStartSecretEncryptionKey, ivString);
        let decrypted = decipher.update(encryptedQrStartSecret, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return {
            ...junkableItems,
            junk: order.junk,
            qrStartSecret: decrypted,
        } as IVerifiedJunk;

    }

    private async handleFailedResponse({response, verifiedJunk, ipAddress}: {
        response: CollectResponse,
        verifiedJunk: IVerifiedJunk,
        ipAddress: string,
    }): Promise<IPollResponse> {
        switch(response.hintCode){
            case 'expiredTransaction':
                {
                    if(verifiedJunk.retriesLeft <= 0){
                        return this.createResponse({collectResponse: response, retriesLeft: 0, verifiedJunk});
                    }
                    return await this.authenticate({request: {endUserIp: ipAddress}, retriesLeft: verifiedJunk.retriesLeft - 1});
                }
            case 'certificateErr':
            case 'userCancel':
            case 'cancelled':
            case 'startFailed':
            default:
                return this.createResponse({collectResponse: response, retriesLeft: 0, verifiedJunk});
        }
    }

    private createQrCode({response, startTime, qrStartSecret, qrStartToken}: {
        response: CollectResponse,
        startTime: number,
        qrStartSecret: string,
        qrStartToken: string,
    }): string {
        if(response === undefined || qrStartToken === undefined){
            return ''
        }
        const time = Math.floor((Date.now() - startTime) / 1000);
        const qrAuthCode = createHmac('sha256', qrStartSecret)
            .update(time.toString())
            .digest('hex');
        const code = `bankid.${qrStartToken}.${time}.${qrAuthCode}`;
        console.log("code", code)
        return code
    }

    async authenticate({request, retriesLeft}: {request: AuthRequest, retriesLeft?: number}): Promise<IPollResponse> {
        if(!this.bankid){
            throw new Error('BankID client not initialized');
        }
        const authResponse = await this.bankid.authenticate(request);
        const collectResponse = await this.bankid.collect({orderRef: authResponse.orderRef});
        return this.createResponse({collectResponse, authResponse, retriesLeft: retriesLeft ?? this.maxRetries});
    }

    async sign({request, retriesLeft}: {request: SignRequest, retriesLeft?: number}): Promise<IPollResponse> {
        if(!this.bankid){
            throw new Error('BankID client not initialized');
        }
        const signResponse = await this.bankid.sign(request);
        const collectResponse = await this.bankid.collect({orderRef: signResponse.orderRef});
        return this.createResponse({collectResponse, signResponse, retriesLeft: retriesLeft ?? this.maxRetries});
    }

    async collect(request: IPollRequest): Promise<IPollResponse> {
        if(!this.verifyJunk(request)){
            throw new Error('Invalid poll request');
        }
        if(!this.bankid){
            throw new Error('BankID client not initialized');
        }
        const verifiedJunk = this.verifyJunk(request);
        const  {orderRef} = verifiedJunk;
        const collectResponse = await this.bankid.collect({orderRef});
        
        switch(collectResponse.status){
            case 'pending':
                return this.createResponse({collectResponse, retriesLeft: request.retriesLeft, verifiedJunk});
            case 'failed':
                return await this.handleFailedResponse({response: collectResponse, verifiedJunk, ipAddress: request.ipAddress});
            case 'complete':
                return await this.createCompleteResponse({collectResponse, verifiedJunk});
            default:
                return this.createResponse({collectResponse, verifiedJunk, retriesLeft: 0});
        }
    }
}

