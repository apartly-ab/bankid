import { CompletionData } from "../bankid";

/**
 * This class is an abstract class that should be extended whenever you need to add another authentication provider.
 */
export default abstract class AuthenticationClient<T>{
    protected abstract checkUserExists(data: CompletionData) : Promise<boolean>;
    protected abstract createUser(data: CompletionData) : Promise<void>;
    protected abstract signInUser(data: CompletionData): Promise<T>;
    abstract run(data: CompletionData): Promise<T>;
}