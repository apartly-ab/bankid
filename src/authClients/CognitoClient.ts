import { CognitoIdentityProviderClient, AdminGetUserCommand, CognitoIdentityProviderServiceException, UserNotFoundException, AdminCreateUserCommand, AdminSetUserPasswordCommand, AdminInitiateAuthCommand, AuthenticationResultType, AdminRespondToAuthChallengeCommand } from "@aws-sdk/client-cognito-identity-provider";
import { CompletionData } from "../bankid";
import AuthenticationClient from "./AuthenticationClient";
import { createHmac } from "crypto";

interface ICognitoAuthClientProps {
    /** The name of the username hash key in the secret store*/
    usernameHashKey: string,
    /** The name of the password hash key in the secret store*/
    passwordHashKey: string,
    /** The AWS region of the Cognito user pool */
    awsRegion: string,
    /** The ID of the Cognito user pool client*/
    cognitoClientId: string,
    /** The ID of the Cognito user pool */
    userPoolId: string,
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
    private usernameHashKey: string;
    private passwordHashKey: string;
    private awsRegion: string;
    private userPoolId: string;
    private cognitoClientId: string;

    constructor({usernameHashKey, passwordHashKey, awsRegion, userPoolId, cognitoClientId} : ICognitoAuthClientProps){
        super();
        this.cognito = new CognitoIdentityProviderClient({
            region: awsRegion
        })
        this.usernameHashKey = usernameHashKey;
        this.passwordHashKey = passwordHashKey;
        this.awsRegion = awsRegion;
        this.userPoolId = userPoolId;
        this.cognitoClientId = cognitoClientId;
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
        const username = createHmac("sha256", this.usernameHashKey).update(data.user.personalNumber).digest("hex");
        return username;
    }

    private async getPassword(data: CompletionData): Promise<string> {
        const password = createHmac("sha256", this.passwordHashKey).update(data.user.personalNumber).digest("hex");
        return password;
    }

    protected async checkUserExists(data: CompletionData): Promise<boolean> {
        const username = await this.getUsername(data);
        const command = new AdminGetUserCommand({
            Username: username,
            UserPoolId: this.userPoolId
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
    protected async createUser(data: CompletionData) {
        const username = await this.getUsername(data);
        const password = await this.getPassword(data);

        const createUserCommand = new AdminCreateUserCommand({
        Username: username,
        UserPoolId: this.userPoolId,
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
        const createUserResult = await this.cognito.send(createUserCommand);            
        if(!createUserResult){
            throw new Error("No result from createUser");
        }
        console.log("createUserResult", createUserResult);
        // Set user password
        const setPasswordCommand = new AdminSetUserPasswordCommand({
            UserPoolId: this.userPoolId,
            Username: username,
            Password:"_"+password,
            Permanent: true
        })
        const setPasswordResult = await this.cognito.send(setPasswordCommand);
        if(!setPasswordResult){
            throw new Error("No result from setPassword");
        }
        console.log("setPasswordResult", setPasswordResult);

        // Initiate auth, should prompt user to change password
        const initiateAuthCommand = new AdminInitiateAuthCommand({
            UserPoolId: this.userPoolId,
            ClientId: this.cognitoClientId,
            AuthFlow: "ADMIN_NO_SRP_AUTH",
            AuthParameters: {
                USERNAME: username,
                PASSWORD: "_"+password,
            }
        })

        const initiateAuthResult = await this.cognito.send(initiateAuthCommand);
        if(!initiateAuthResult){
            throw new Error("No result from initiateAuth");
        }
        console.log("initiateAuthResult", initiateAuthResult);

        //We expect the CHALLENGE_NAME to be NEW_PASSWORD_REQUIRED
        if(initiateAuthResult.ChallengeName !== "NEW_PASSWORD_REQUIRED"){
            throw new Error("Unexpected challenge name: " + initiateAuthResult.ChallengeName);
        }

        // Set user password
        const respondToAuthChallengeCommand = new AdminRespondToAuthChallengeCommand({
            UserPoolId: this.userPoolId,
            ClientId: this.cognitoClientId,
            ChallengeName: "NEW_PASSWORD_REQUIRED",
            ChallengeResponses: {
                USERNAME: username,
                NEW_PASSWORD: password,
            },
            Session: initiateAuthResult.Session
        })

        const respondToAuthChallengeResult = await this.cognito.send(respondToAuthChallengeCommand);
        if(!respondToAuthChallengeResult){
            throw new Error("No result from respondToAuthChallenge");
        }
        console.log("respondToAuthChallengeResult", respondToAuthChallengeResult);

        //We expect authentication result to be present
        if(!respondToAuthChallengeResult.AuthenticationResult){
            throw new Error("No authentication result found");
        }
        return respondToAuthChallengeResult.AuthenticationResult;
        
    }
    protected async signInUser(data: CompletionData): Promise<AuthenticationResultType> {
        const username = await this.getUsername(data);
        const password = await this.getPassword(data);

        const command = new AdminInitiateAuthCommand({
            UserPoolId: this.userPoolId,
            ClientId: this.cognitoClientId,
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
        throw new Error("No authentication result found" + JSON.stringify(response));
    }

    async run(data: CompletionData): Promise<AuthenticationResultType> {
        const exists = await this.checkUserExists(data);
        if(exists){
            return this.signInUser(data);
        }
        else{
            return this.createUser(data);
        }
    }
}