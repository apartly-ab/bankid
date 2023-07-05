import SecretStore from "./SecretStore";
import {SecretsManagerClient, GetSecretValueCommand} from '@aws-sdk/client-secrets-manager'

const awsRegion = process.env.AWS_REGION as string;

if(!awsRegion){
    throw new Error("AWS_REGION not set")
}

/**
 * This is a store that can be used to fetch secrets from AWS Secrets Manager.
 */
export default class SecretsManagerStore extends SecretStore {
    private client: SecretsManagerClient;

    constructor(){
        super();
        this.client = new SecretsManagerClient({
            region: awsRegion,
        })
    }

    async get(key: string): Promise<string> {
        if(this.localStore[key]){
            return this.localStore[key];
        }
        const response = await this.client.send(new GetSecretValueCommand({
            SecretId: key
        }))
        if(response.SecretString){
            this.localStore[key] = response.SecretString;
            return response.SecretString;
        }
        throw new Error("No secret string found")
    }
}