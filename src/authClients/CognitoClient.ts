import { CognitoIdentityProviderClient, AdminGetUserCommand, CognitoIdentityProviderServiceException, UserNotFoundException, AdminCreateUserCommand, AdminSetUserPasswordCommand, AdminInitiateAuthCommand, AuthenticationResultType } from "@aws-sdk/client-cognito-identity-provider";
import { CompletionData } from "../bankid";
import AuthenticationClient from "./AuthenticationClient";
import SecretStore from "../secretStores/SecretStore";
import { createHmac } from "crypto";

const awsRegion = process.env.AWS_REGION as string;
const userPoolId = process.env.COGNITO_USER_POOL_ID as string;
const cognitoClientId = process.env.COGNITO_CLIENT_ID as string;


if(!awsRegion){
    throw new Error("AWS_REGION not set")
}
if(!userPoolId){
    throw new Error("COGNITO_USER_POOL_ID not set")
}

interface ICognitoAuthClientProps {
    secretStore: SecretStore,
    /** The name of the username hash key in the secret store*/
    usernameHashKeyName: string,
    /** The name of the password hash key in the secret store*/
    passwordHashKeyName: string,
}

/**
 * Cognito authentication client.
 * This client is a plug-in for the BankID authentication service. Use it to connect your BankID service to a Cognito user pool.
 * It must be provided with a secret store that contains the username and password hash keys.
 * It also needs the *keys* to these keys in the secret store.
 * This is a requirement so that the developer does not forget to add the keys to the secret store.
 */
export default class CognitoAuthClient extends AuthenticationClient<AuthenticationResultType> {
    private cognito: CognitoIdentityProviderClient;
    private secretStore: SecretStore;
    private usernameHashKeyName: string;
    private passwordHashKeyName: string;

    constructor({secretStore, usernameHashKeyName, passwordHashKeyName} : ICognitoAuthClientProps){
        super();
        this.cognito = new CognitoIdentityProviderClient({
            region: awsRegion
        })
        this.secretStore = secretStore;
        this.usernameHashKeyName = usernameHashKeyName;
        this.passwordHashKeyName = passwordHashKeyName;
    }
    protected async handleCompletion(data: CompletionData){
        const userExists = await this.checkUserExists(data);
        if(userExists){
            await this.signInUser(data);
        } else {
            await this.createUser(data);
        }
    }

    private async getUsername(data: CompletionData): Promise<string> {
        const usernameHashKey = await this.secretStore.get(this.usernameHashKeyName);
        const username = createHmac("sha256", usernameHashKey).update(data.user.personalNumber).digest("hex");
        return username;
    }

    private async getPassword(data: CompletionData): Promise<string> {
        const passwordHashKey = await this.secretStore.get(this.passwordHashKeyName);
        const password = createHmac("sha256", passwordHashKey).update(data.user.personalNumber).digest("hex");
        return password;
    }

    protected async checkUserExists(data: CompletionData): Promise<boolean> {
        const username = await this.getUsername(data);
        const command = new AdminGetUserCommand({
            Username: username,
            UserPoolId: userPoolId
        })
        try {
            await this.cognito.send(command);
            return true;
        } catch (error) {
            const cognitoError = error as CognitoIdentityProviderServiceException;
            if(cognitoError instanceof UserNotFoundException){
                return false;
            }
            throw error;
        }

    }
    /**
     * Creates a new user in a Cognito user pool, based on the data from BankID.
     * @param data 
     */
    protected async createUser(data: CompletionData): Promise<void> {
        const username = await this.getUsername(data);
        const password = await this.getPassword(data);

        const createUserCommand = new AdminCreateUserCommand({
        Username: username,
        UserPoolId: userPoolId,
        UserAttributes: [
            {
                Name: "custom:personal_number",
                Value: data.user.personalNumber
            },
            {
                Name: "given_name",
                Value: data.user.givenName
            },
            {
                Name: "family_name",
                Value: data.user.surname
            },
        ]
        })
        await this.cognito.send(createUserCommand);            
    
        const setPasswordCommand = new AdminSetUserPasswordCommand({
            Username: username,
            UserPoolId: userPoolId,
            Password: password,
        })
        await this.cognito.send(setPasswordCommand);
    }
    protected async signInUser(data: CompletionData): Promise<AuthenticationResultType> {
        const username = await this.getUsername(data);
        const password = await this.getPassword(data);

        const command = new AdminInitiateAuthCommand({
            UserPoolId: userPoolId,
            ClientId: cognitoClientId,
            AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password,
            }
        })
        const response = await this.cognito.send(command);
        if(response.AuthenticationResult){
            return response.AuthenticationResult;
        }
        throw new Error("No authentication result found")
    }

    async run(data: CompletionData): Promise<AuthenticationResultType> {
        const exists = await this.checkUserExists(data);
        if(exists){
            return this.signInUser(data);
        }
        else{
            await this.createUser(data);
            return this.signInUser(data);
        }
    }
}