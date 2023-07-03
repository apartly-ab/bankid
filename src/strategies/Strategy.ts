import { createHmac } from "crypto";
import { AuthRequest, AuthResponse, BankIdClient, CollectRequest, CollectResponse, SignRequest, SignResponse } from "../bankid";


export default abstract class BankIdStrategy {
    protected abstract authRequest: AuthRequest | undefined;
    protected abstract signRequest: SignRequest | undefined;
    protected abstract authResponse: AuthResponse | undefined;
    protected abstract signResponse: SignResponse | undefined;
    protected abstract bankid: BankIdClient | undefined;
    protected abstract currentOrderStartTime: number;
    protected cleanUp: () => void = () => {};
    protected createQrCode(){
        const response = this.authResponse || this.signResponse;
        if(!this.currentOrderStartTime || !response){
            console.log(this.currentOrderStartTime)
            return "";
        }
        const time = Math.floor(Date.now() - this.currentOrderStartTime) / 1000;
        const qrAuthCode = createHmac('sha256', response.qrStartSecret)
            .update(time.toString())
            .digest('hex');
        const code = `bankid.${response.qrStartToken}.${time}.${qrAuthCode}`;
        console.log("code", code)
        return code
    }

    protected abstract handleAuthResponse(response: AuthResponse): void;
    protected abstract handleSignResponse(response: SignResponse): void;

    protected abstract cancelOrder(): void;

    protected abstract handlePending(response: CollectResponse): void;
    protected abstract handleComplete(response: CollectResponse): void;
    protected abstract handleFailures(response: CollectResponse): void;
    /**
     * Attach the strategy to a BankIdClient. This creates event listeners on the client
     * that will call the strategy methods when the events are emitted.
     * 
     * @param client 
    */
   attach(client: BankIdClient){
        const handleAuthResponse = this.handleAuthResponse.bind(this);
        const handleSignResponse = this.handleSignResponse.bind(this);
        const handlePending = this.handlePending.bind(this);
        const handleComplete = this.handleComplete.bind(this);
        const handleFailures = this.handleFailures.bind(this);

        this.bankid = client
        .on("auth:start", handleAuthResponse)
        .on("sign:start", handleSignResponse)
        .on("collect:pending", handlePending)
        .on("collect:complete", handleComplete)
        .on("collect:failed", handleFailures)

        this.cleanUp = () => {
            this.bankid = undefined;
            client
            .off("auth:start", handleAuthResponse)
            .off("sign:start", handleSignResponse)
            .off("collect:pending", handlePending)
            .off("collect:complete", handleComplete)
            .off("collect:failed", handleFailures)
        }

    }

    /**
     * Renews the authentication order. This is mostly used when the user did not finish the order before it expired.
     * @returns void
     */
    protected async renewAuthentication(){
        if(!this.authResponse || !this.authRequest || !this.bankid){
            return;
        }
        this.cancelOrder();
        this.cancelOrder = await this.bankid.authenticateAndCollect(this.authRequest);
    }

    /**
     * Renews the signing order. This is mostly used when the user did not finish the order before it expired.
     * @returns void
     */
    protected async renewSigning(){
        if(!this.signResponse || !this.signRequest || !this.bankid){
            return;
        }
        this.cancelOrder();
        this.cancelOrder = await this.bankid.signAndCollect(this.signRequest);
    }
}