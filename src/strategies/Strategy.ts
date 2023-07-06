import { createHmac } from "crypto";
import { AuthRequest, AuthResponse, BankIdClient, CollectRequest, CollectResponse, SignRequest, SignResponse, BankIdDevice } from "../bankid";
import AuthenticationClient from "../authClients/AuthenticationClient";

export interface IBankIdStrategyProps<SuccessType> {
    authClient: AuthenticationClient<SuccessType>,
    bankid: BankIdClient,
    device: BankIdDevice
}

export default abstract class BankIdStrategy<SuccessType> {
    protected abstract authRequest: AuthRequest | undefined;
    protected abstract signRequest: SignRequest | undefined;
    protected abstract authResponse: AuthResponse | undefined;
    protected abstract signResponse: SignResponse | undefined;
    protected device: BankIdDevice;
    protected authClient: AuthenticationClient<SuccessType>;
    protected used: boolean = false;
    protected abstract bankid: BankIdClient | undefined;
    protected abstract currentOrderStartTime: number;
    protected cleanUp: () => void = () => {};
    protected createQrCode(){
        const response = this.authResponse || this.signResponse;
        if(!this.currentOrderStartTime || !response){
            console.log(this.currentOrderStartTime)
            return "";
        }
        const time = Math.floor(Date.now() - this.currentOrderStartTime / 1000);
        const qrAuthCode = createHmac('sha256', response.qrStartSecret)
            .update(time.toString())
            .digest('hex');
        const code = `bankid.${response.qrStartToken}.${time}.${qrAuthCode}`;
        console.log("code", code)
        return code
    }

    protected use() : BankIdClient | never{
        if(this.used){
            throw new Error("Strategy already used");
        }
        this.used = true;
        if(!this.bankid){
            console.log(this)
            throw new Error("BankId client not attached");
        }
        return this.bankid;
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

        this.bankid = client;
        this.bankid
        .on("auth:start", handleAuthResponse)
        .on("sign:start", handleSignResponse)
        .on("collect:pending", handlePending)
        .on("collect:complete", handleComplete)
        .on("collect:failed", handleFailures)

        console.log(this.bankid, "attached")

        this.cleanUp = () => {
            console.log("detached")
            if(!this.bankid){
                return;
            }
            this.bankid
            .off("auth:start", handleAuthResponse)
            .off("sign:start", handleSignResponse)
            .off("collect:pending", handlePending)
            .off("collect:complete", handleComplete)
            .off("collect:failed", handleFailures)
            this.bankid = undefined;
        }

    }

    constructor({authClient, bankid, device} : IBankIdStrategyProps<SuccessType>){
        this.authClient = authClient;
        this.attach = this.attach.bind(this);
        this.use = this.use.bind(this);
        this.attach(bankid);
        this.device = device;
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