
/**
 * This class is an abstract class that should be extended whenever you want to add another way to store secrets.
 */
export default abstract class SecretStore{
    abstract get(key: string): Promise<string | never>;
    protected localStore: {[key: string]: string} = {};
}