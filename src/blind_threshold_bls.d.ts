/* tslint:disable */
/* eslint-disable */
/**
* Given a message and a seed, it will blind it and return the blinded message
*
* * message: A cleartext message which you want to blind
* * seed: A 32 byte seed for randomness. You can get one securely via `crypto.randomBytes(32)`
*
* Returns a `BlindedMessage`. The `BlindedMessage.blinding_factor` should be saved for unblinding any
* signatures on `BlindedMessage.message`
*
* # Safety
* - If the same seed is used twice, the blinded result WILL be the same
* @param {Uint8Array} message 
* @param {Uint8Array} seed 
* @returns {BlindedMessage} 
*/
export function blind(message: Uint8Array, seed: Uint8Array): BlindedMessage;
/**
* Given a blinded message and a pointer to the blinding_factor used for blinding, it returns the message
* unblinded
*
* * blinded_message: A message which has been blinded or a blind signature
* * blinding_factor: The blinding_factor used to blind the message
*
* # Throws
*
* - If unblinding fails.
*
* # Safety
*
* - The `blinding_factor` is a pointer. If an invalid pointer value is given, this will panic.
* @param {Uint8Array} blinded_signature 
* @param {number} blinding_factor 
* @returns {Uint8Array} 
*/
export function unblind(blinded_signature: Uint8Array, blinding_factor: number): Uint8Array;
/**
* Verifies the signature after it has been unblinded. Users will call this on the
* threshold signature against the full public key
*
* * public_key: The public key used to sign the message
* * message: The message which was signed
* * signature: The signature which was produced on the message
*
* # Throws
*
* - If verification fails
*
* # Safety
*
* - The `public_key` is a pointer. If an invalid pointer value is given, this will panic.
* @param {number} public_key 
* @param {Uint8Array} message 
* @param {Uint8Array} signature 
*/
export function verify(public_key: number, message: Uint8Array, signature: Uint8Array): void;
/**
* Signs the message with the provided private key and returns the signature
*
* # Throws
*
* - If signing fails
*
* # Safety
*
* - The `private_key` is a pointer. If an invalid pointer value is given, this will panic.
* @param {number} private_key 
* @param {Uint8Array} message 
* @returns {Uint8Array} 
*/
export function sign(private_key: number, message: Uint8Array): Uint8Array;
/**
* Signs the message with the provided **share** of the private key and returns the **partial**
* signature.
*
* # Throws
*
* - If signing fails
*
* NOTE: This method must NOT be called with a PrivateKey which is not generated via a
* secret sharing scheme.
*
* # Safety
* - The `private_key` is a pointer. If an invalid pointer value is given, this will panic.
* @param {number} share 
* @param {Uint8Array} message 
* @returns {Uint8Array} 
*/
export function partialSign(share: number, message: Uint8Array): Uint8Array;
/**
* Verifies a partial signature against the public key corresponding to the secret shared
* polynomial.
*
* # Throws
*
* - If verification fails
*
* # Safety
* - The `polynomial` is a pointer. If an invalid pointer value is given, this will panic.
* @param {number} polynomial 
* @param {Uint8Array} blinded_message 
* @param {Uint8Array} sig 
*/
export function partialVerify(polynomial: number, blinded_message: Uint8Array, sig: Uint8Array): void;
/**
* Combines a flattened vector of partial signatures to a single threshold signature
*
* NOTE: Wasm-bindgen does not support Vec<Vec<u8>>, so this function accepts a flattened
* byte vector which it will parse in chunks for each signature.
*
* NOTE: If you are working with an array of Uint8Arrays In Javascript, the simplest
* way to flatten them is via:
*
* ```js
* function flatten(arr) {
*     return Uint8Array.from(arr.reduce(function(a, b) {
*         return Array.from(a).concat(Array.from(b));
*     }, []));
* }
* ```
*
* # Throws
*
* - If the aggregation fails
*
* # Safety
*
* - This function does not check if the signatures are valid!
* @param {number} threshold 
* @param {Uint8Array} signatures 
* @returns {Uint8Array} 
*/
export function combine(threshold: number, signatures: Uint8Array): Uint8Array;
/**
* Generates a t-of-n polynomial and private key shares
*
* # Safety
*
* WARNING: This is a helper function for local testing of the library. Do not use
* in production, unless you trust the person that generated the keys.
*
* The seed MUST be at least 32 bytes long
* @param {number} n 
* @param {number} t 
* @param {Uint8Array} seed 
* @returns {Keys} 
*/
export function thresholdKeygen(n: number, t: number, seed: Uint8Array): Keys;
/**
* Generates a single private key from the provided seed.
*
* # Safety
*
* The seed MUST be at least 32 bytes long
* @param {Uint8Array} seed 
* @returns {Keypair} 
*/
export function keygen(seed: Uint8Array): Keypair;
export class BlindedMessage {
  free(): void;
  readonly blindingFactorPtr: number;
  readonly message: Uint8Array;
}
export class Keypair {
  free(): void;
  readonly privateKeyPtr: number;
  readonly publicKeyPtr: number;
}
export class Keys {
  free(): void;
/**
* @param {number} index 
* @returns {number} 
*/
  getSharePtr(index: number): number;
/**
* @returns {number} 
*/
  numShares(): number;
  n: number;
  readonly polynomialPtr: number;
  readonly sharesPtr: number;
  t: number;
  readonly thresholdPublicKeyPtr: number;
}
