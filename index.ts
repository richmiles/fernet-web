/**
 * @author Rich Miles
 * @date December 05, 2022
 * 
 * This code provides an implementation of the Fernet symmetric encryption algorithm
 * using the Web Crypto API.
 * 
 * @warning This code is provided as is, without any warranty or guarantees. Use at your own risk.
 * 
 * @example
 * // Create a new Fernet instance using a secret key
 * const fernet = await Fernet.create("-lf4DsgLkOaE1GbtIQKNGU1NPQByMDKP2a6Enl9rclE=");
 * 
 * // Encrypt a message
 * const encryptedToken = await fernet.encrypt("Hello world!");
 * 
 * // Decrypt the encrypted message
 * const decryptedMessage = await fernet.decrypt(encryptedToken);
 * 
 * // Print the decrypted message
 * console.log(decryptedMessage); // Hello world!
 */

/**
 * Fernet is a simple and secure way to encrypt and decrypt messages using symmetric encryption.
 */
export default class Fernet {
    private signingKey: CryptoKey;
    private encryptionKey: CryptoKey;

    /**
     * Create a new Fernet instance with the provided signing and encryption keys.
     * @param signingKey - A CryptoKey to use for signing messages.
     * @param encryptionKey - A CryptoKey to use for encrypting and decrypting messages.
     */
    private constructor(signingKey: CryptoKey, encryptionKey: CryptoKey) {
        this.signingKey = signingKey
        this.encryptionKey = encryptionKey
    }

    /**
     * Generate signing and encryption keys from a secret key.
     * @param secretKeyBuffer - A Uint8Array containing the secret key to use.
     * @returns A tuple containing the signing and encryption keys.
     */
    private static async initializeKeys(secretKeyBuffer: Uint8Array): Promise<{ signingKey: CryptoKey, encryptionKey: CryptoKey }> {
        const signingKeyBuffer = secretKeyBuffer.slice(0, 16);
        const encryptionKeyBuffer = secretKeyBuffer.slice(16);

        const signingKey = await crypto.subtle.importKey(
            "raw",
            signingKeyBuffer,
            {
                name: "HMAC",
                hash: "SHA-256",
            },
            false,
            ["verify", "sign"]
        );

        const encryptionKey = await crypto.subtle.importKey(
            "raw",
            encryptionKeyBuffer,
            "AES-CBC",
            false,
            ["encrypt", "decrypt"]
        );

        return { signingKey, encryptionKey }
    }

    /**
     * Create a new Fernet instance with a secret key.
     * @param secretKey_b64 - A base64-encoded string representation of the secret key to use.
     * If null, a new secret key will be generated.
     * @returns A new Fernet instance.
    */
    public static async create(secretKey_b64: string | null): Promise<Fernet> {
        var secretKeyBuffer = new Uint8Array(32)
        if (secretKey_b64 != null) {
            // Decode the URL-safe base64-encoded secret key
            secretKeyBuffer = Uint8Array.from(window.atob(secretKey_b64.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));
        }
        else {
            // Create a new secret key from scratch to use for this session
            crypto.getRandomValues(secretKeyBuffer)
        }
        const keys = await Fernet.initializeKeys(secretKeyBuffer)
        return new Fernet(keys.signingKey, keys.encryptionKey)
    }

        /**
    Encrypt a message into a Fernet token.
    @param plainText - The message to encrypt.
    @returns A base64-encoded Fernet token.
    */
    public async encrypt(plainText: string): Promise<string> {

        const plainTextBuffer = new TextEncoder().encode(plainText)
        const ivBuffer = new Uint8Array(16); // create a new array to store the IV

        // generate the random IV
        crypto.getRandomValues(ivBuffer);

        // Encrypt the plain text
        const encryptedMessage = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv: ivBuffer },
            this.encryptionKey,
            plainTextBuffer
        );

        // Version is always the first byte and always 128 (0x80)
        const version = new Uint8Array([0x80]);

        // The time bytes are a big-endian encoded uint64 of unix epoch time (seconds)
        const timeBuffer = new ArrayBuffer(8);
        const view = new DataView(timeBuffer);
        const currentTime = Date.now();
        const unixEpochTime = Math.round(currentTime / 1000);
        view.setBigUint64(0, BigInt(unixEpochTime), false);
        const timestamp = new Uint8Array(timeBuffer);

        // Convert the IV to a Uint8Array
        const iv = new Uint8Array(ivBuffer);

        // Convert the encrtyped message to a Uint8Array
        const ciphertext = new Uint8Array(encryptedMessage);

        // Concatenate the unsigned component
        const unsigned_token = new Uint8Array([
            ...version,
            ...timestamp,
            ...iv,
            ...ciphertext,
        ])

        // Compute the HMAC signature
        const hmac = new Uint8Array(await crypto.subtle.sign(
            { name: "HMAC", hash: "SHA-256", },
            this.signingKey,
            unsigned_token)
        );

        // Concatenate the header with the signature
        const signed_token = new Uint8Array([
            ...version,
            ...timestamp,
            ...iv,
            ...ciphertext,
            ...hmac
        ])

        // Convert the signed token array to a URL-Safe base64 string
        // Note: The signed_token array is a Uint8Array, but the btoa function expects a string.
        // Originally, this was using String.fromCharCode(signed_token), but that was causing
        // a stack overflow with large arrays. This is a workaround that avoids the stack overflow.
        let tokenChars: string[] = [];
        signed_token.forEach(byte => {
            tokenChars.push(String.fromCharCode(byte));
        });
        const fernetToken = window.btoa(tokenChars.join(""))
            .replace(/\+/g, "-")
            .replace(/\//g, "_");

        return fernetToken
    }


    /**
     * Decrypt a Fernet token and return the plain text message.
     * @param token_b64 - A base64-encoded Fernet token.
     * @returns The decrypted message as a string.
     */
    public async decrypt(token_b64: string): Promise<string> {
        // Decode the base64-encoded secret key

        // Convert the URL-safe base 64 value to a Uint8Array
        const tokenBuffer = Uint8Array.from(window.atob(token_b64.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));

        // Decompose the token into its various parts
        const version = tokenBuffer.slice(0, 1);
        const timestamp = tokenBuffer.slice(1, 9);
        const iv = tokenBuffer.slice(9, 25);
        const ciphertext = tokenBuffer.slice(25, -32);
        const hmac = tokenBuffer.slice(-32);


        // Decrypt the cipher text
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: iv,
            },
            this.encryptionKey,
            ciphertext
        );
        const decryptedMessage = new TextDecoder().decode(decrypted);


        // Verify the HMAC signature
        const unsigned_token = new Uint8Array([
            ...version,
            ...timestamp,
            ...iv,
            ...ciphertext,
        ])

        const verification = await crypto.subtle.verify(
            { name: "HMAC", hash: "SHA-256" },
            this.signingKey,
            hmac,
            unsigned_token,
        )

        if (!verification) {
            throw new InvalidTokenError("Token is invalid or has been tampered with");
        }

        return decryptedMessage;

    }
}

/**
 * The InvalidTokenError class is used to indicate that a Fernet token failed to verify.
*/
class InvalidTokenError extends Error {
    /*
    Create a new InvalidTokenError instance.
    @param message - A string describing the error that occurred.
    */
    constructor(message: string) {
        super(message);
    }
}