# Fernet Encryption Library for Web Crypto API
This library provides an implementation of the Fernet symmetric encryption algorithm using the Web Crypto API. Fernet is a simple and secure way to encrypt and decrypt messages using symmetric encryption.

> _It should be noted that while Fernet encryption can be a secure way to encrypt data, using it in the browser is inhernetly insecure. Since the secret key used for encryption is stored in the client's browser, it can be accessed by anyone with knowledge of how to inspect the page source._

## Installation
To use this library, you can install it via npm:

<pre><code>```node
npm install fernet-web
```
</code></pre>

## Usage
Here is an example of how to use this library to encrypt and decrypt a message:

<pre><code>```typescript 
import Fernet, { InvalidTokenError } from 'fernet';

// Create a new Fernet instance using a secret key
const fernet = await Fernet.create("-lf4DsgLkOaE1GbtIQKNGU1NPQByMDKP2a6Enl9rclE=");

// Encrypt a message
const encryptedToken = await fernet.encrypt("Hello world!");

// Decrypt the encrypted message
const decryptedMessage = await fernet.decrypt(encryptedToken);

// Print the decrypted message
console.log(decryptedMessage); // Hello world!
```
</code></pre>

## API
### Fernet
The **`Fernet`** class is used to create and use Fernet encryption instances.

### `create(secretKey_b64: string | null): Promise<Fernet>`

Creates a new instance of the `Fernet` class with the provided secret key. If `secretKey_b64` is `null`, a new secret key is generated.

#### Parameters:

- **`secretKey_b64`**: A base64-encoded string representation of the secret key to use. If `null`, a new secret key will be generated.

#### Returns:

A promise that resolves with a new `Fernet` instance.

### `encrypt(plainText: string): Promise<string>`
Encrypt a message into a Fernet token.

#### Parameters
- **`plainText`**: The message to encrypt.

#### Returns: 
A promise that resolves with a base64-encoded Fernet token.

### `decrypt(token_b64: string): Promise<string>`
Decrypt a Fernet token and return the plain text message.

#### Parameters
- **`token_b64`**: A base64-encoded Fernet token.

#### Returns: 
The decrypted message as a string.

## License
This code is provided as is, without any warranty or guarantees. Use at your own risk.

## Author
Written by Rich Miles (me@richmiles.xyz) on December 05, 2022.