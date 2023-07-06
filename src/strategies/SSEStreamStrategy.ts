import { createHmac } from "crypto";
import { AuthRequest, AuthResponse, BankIdClient, CollectResponse, PendingHintCode, SignRequest, SignResponse } from "../bankid";
import BankIdStrategy, { IBankIdStrategyProps } from "./Strategy";

interface IClientEvent {
    hintCode?: CollectResponse['hintCode'];
    status: CollectResponse['status'];
    qrCode?: string;
}

abstract class SSEvent<T> {
    abstract type: string;
    data: T;
    constructor(data: T){
        this.data = data;
    }
    toString(){
        return `event: ${this.type}\ndata: ${this.data}\n\n`;
    }

}
export interface ISSFailureEvent {
    reason: string;
}
export class SSFailureEvent extends SSEvent<ISSFailureEvent> {
    type = "failure";
    constructor({reason} : ISSFailureEvent){
        super({reason});
    }
}
export interface ISSNewOrderEvent {
    hintCode: CollectResponse['hintCode'],
    qrCode: string,
    orderRef: string,
    autoStartToken: string,
    orderRefHmac: string,
}
export class SSNewOrderEvent extends SSEvent<ISSNewOrderEvent> {
    type = "newOrder";
    constructor({hintCode, qrCode, orderRef, orderRefHmac, autoStartToken} : ISSNewOrderEvent){
        super({hintCode, qrCode, orderRef, orderRefHmac, autoStartToken});
    }
}

export interface ISSPendingEvent {
    hintCode: PendingHintCode,
    qrCode: string,
}
export class SSPendingEvent extends SSEvent<ISSPendingEvent> {
    type = "pending";
    constructor({hintCode, qrCode} : ISSPendingEvent){
        super({hintCode, qrCode});
    }
}


export class SSSuccessEvent<SuccessType> extends SSEvent<SuccessType> {
    type = "success";
    constructor(props: SuccessType){
        super(props);
    }
}

interface ISSEStreamStrategyProps<SuccessType> extends IBankIdStrategyProps<SuccessType>{
    responseStream:NodeJS.WritableStream,
    options?: {
        maxEndTime?: number,
    },
    orderRefHashKey: string
}

/**
 * The SSE Stream strategy is a strategy that uses Server Sent Events to communicate with the client.
 * The client needs to handle the events and update the UI accordingly.
 * This strategy requires that the runtime supports SSE and that it can stay alive for the duration of the authentication/signing.
 * This is the flow:
 * 
 * First, the strategy is attached to the BankIdClient.
 * Depending on the type of request, you should either call "authenticate" or "sign" on the strategy.
 * When we have called one of the methods, the process will start.
 * 
 * The two most common cases are that the user wants to authenticate by scanning a QR code with their phone, or that
 * they are authenticating with only their phone and no QR code.
 * 
 * ### Case 1: QR Code
 * In this case, we never stop sending events to the client, and the client should update the UI accordingly.
 * 
 * ### Case 2: Mobile only
 * In the second case, we should stop sending events as soon as we know that the user has started the BankID app. 
 * This is because the browser will likely be severely throttled or even killed by the OS if it is not in focus.
 * While it may be able to resume the connection when the user returns to the browser, it is not guaranteed, so
 * we might as well enforce that as a rule. Here, we recommend using the page visibility API to have the browser 
 * resume the connection on the "visibilitychange" event.
 * 
 * ### Case 3: BankID on file or smart card
 * In this case, the browser is not likely to be throttled or killed, so we can keep sending events until the process is done.
 * 
 */
export default class SSESTreamStrategy<SuccessType> extends BankIdStrategy<SuccessType>{
    private responseStream: NodeJS.WritableStream;
    protected authResponse: AuthResponse | undefined;
    protected authRequest : AuthRequest | undefined;
    protected signRequest : SignRequest | undefined;
    protected signResponse: SignResponse | undefined;
    private orderRefHashKey: string | undefined;
    protected bankid: BankIdClient | undefined;
    protected currentOrderStartTime: number = 0;
    protected cancelOrder : () => void = () => {};
    private maxEndTime: number = 0;

    constructor({responseStream, options, authClient, bankid, orderRefHashKey}: ISSEStreamStrategyProps<SuccessType>){
        super({authClient, bankid});
        this.responseStream = responseStream;
        this.orderRefHashKey = orderRefHashKey;
        if(options && options.maxEndTime){
            this.maxEndTime = options.maxEndTime;
        }
    }

    protected async handleAuthResponse(response: AuthResponse){
        if(!this.orderRefHashKey){
            throw new Error("No order ref hash key");
        }
        console.log("Auth response", response);
        this.authResponse = response;
        const newOrderEvent = new SSNewOrderEvent({
            autoStartToken: response.autoStartToken,
            orderRef: response.orderRef,
            orderRefHmac: createHmac('sha256', this.orderRefHashKey).update(response.orderRef).digest('hex'),
            qrCode: this.createQrCode(),
            hintCode: "outstandingTransaction",
        })
        this.responseStream.write(newOrderEvent.toString());
    }
    protected async handleSignResponse(response: SignResponse){
        if(!this.orderRefHashKey){
            throw new Error("No order ref hash key");
        }
        this.signResponse = response;
        const newOrderEvent = new SSNewOrderEvent({
            autoStartToken: response.autoStartToken,
            orderRef: response.orderRef,
            orderRefHmac: createHmac('sha256', this.orderRefHashKey).update(response.orderRef).digest('hex'),
            qrCode: this.createQrCode(),
            hintCode: "outstandingTransaction",
        })
        this.responseStream.write(newOrderEvent.toString());
    }

    private closeConnection<T extends SSEvent<object>>(event: T){
        this.responseStream.write(event.toString());
        this.responseStream.end();
    }

    protected async handleFailures(response: CollectResponse){
        switch(response.hintCode){
            case 'expiredTransaction':
            case 'startFailed':
                if(Date.now() < this.maxEndTime && this.authResponse){
                    console.log("Start failed, retrying")
                    return this.renewAuthentication();
                } else if(Date.now() < this.maxEndTime && this.signResponse){
                    console.log("Start failed, retrying")
                    return this.renewSigning();
                }
                break;
            case 'certificateErr':
            case 'userCancel':
            case 'cancelled':
            default:{
                const failureEvent = new SSFailureEvent({
                    reason: response.hintCode || 'unknown',
                })

                this.closeConnection(failureEvent);
                break;
            }
        }
    }

    protected async handlePending(response: CollectResponse){
        const pendingEvent = new SSPendingEvent({
            hintCode: response.hintCode as PendingHintCode,
            qrCode: this.createQrCode(),
        })
        this.responseStream.write(pendingEvent.toString());
    }

    protected async handleComplete(response: CollectResponse){
        const completionData = response.completionData;
        if(!completionData){
            throw new Error("No completion data");
        }
        const result = await this.authClient.run(completionData);
        const successEvent = new SSSuccessEvent({result})
        this.closeConnection(successEvent);
    }

    protected use() {
        this.currentOrderStartTime = Date.now();
        this.maxEndTime = this.currentOrderStartTime + 5 * 60 * 1000;
        return super.use();
    }

    async authenticate(request: AuthRequest){
        const bankid = this.use()
        this.authRequest = request;
        this.cancelOrder = await bankid.authenticateAndCollect(request);
    }

    async sign(request: SignRequest){
        const bankid = this.use()
        this.signRequest = request;
        this.cancelOrder = await bankid.signAndCollect(request);
    }

    /**
     * Final collect
     * 
     * This method should be called whenever we expect that the user has finished authentication in the BankID app.
     * This is only relevant for the case where the user is authenticating with only their phone and no QR code.
     * @param orderRef 
     */
    async finalCollect(orderRef: string){
        const bankid = this.use()
        await bankid.finalCollect(orderRef);
    }

}