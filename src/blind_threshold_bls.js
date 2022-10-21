let imports = {};
imports['__wbindgen_placeholder__'] = module.exports;
let wasm;

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachegetUint8Memory0 = null;
function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

const heap = new Array(32).fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function getObject(idx) { return heap[idx]; }

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachegetInt32Memory0 = null;
function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
        cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
}

function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
* Generates a single private key from the provided seed.
*
* # Safety
*
* The seed MUST be at least 32 bytes long
* @param {Uint8Array} seed
* @returns {Keypair}
*/
module.exports.keygen = function(seed) {
    var ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.keygen(ptr0, len0);
    return Keypair.__wrap(ret);
};

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
module.exports.thresholdKeygen = function(n, t, seed) {
    var ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.thresholdKeygen(n, t, ptr0, len0);
    return Keys.__wrap(ret);
};

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
        module.exports.combine = function(threshold, signatures) {
            var ptr0 = passArray8ToWasm0(signatures, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            wasm.combine(8, threshold, ptr0, len0);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v1;
        };

        /**
        * Verifies a partial *blind* signature against the public key corresponding to the secret shared
        * polynomial.
        *
        * # Throws
        *
        * - If verification fails
        * @param {Uint8Array} polynomial_buf
        * @param {Uint8Array} blinded_message
        * @param {Uint8Array} sig
        */
        module.exports.partialVerifyBlindSignature = function(polynomial_buf, blinded_message, sig) {
            var ptr0 = passArray8ToWasm0(polynomial_buf, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(blinded_message, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            var ptr2 = passArray8ToWasm0(sig, wasm.__wbindgen_malloc);
            var len2 = WASM_VECTOR_LEN;
            wasm.partialVerifyBlindSignature(ptr0, len0, ptr1, len1, ptr2, len2);
        };

        /**
        * Verifies a partial signature against the public key corresponding to the secret shared
        * polynomial.
        *
        * # Throws
        *
        * - If verification fails
        * @param {Uint8Array} polynomial_buf
        * @param {Uint8Array} blinded_message
        * @param {Uint8Array} sig
        */
        module.exports.partialVerify = function(polynomial_buf, blinded_message, sig) {
            var ptr0 = passArray8ToWasm0(polynomial_buf, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(blinded_message, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            var ptr2 = passArray8ToWasm0(sig, wasm.__wbindgen_malloc);
            var len2 = WASM_VECTOR_LEN;
            wasm.partialVerify(ptr0, len0, ptr1, len1, ptr2, len2);
        };

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
        * @param {Uint8Array} share_buf
        * @param {Uint8Array} message
        * @returns {Uint8Array}
        */
        module.exports.partialSignBlindedMessage = function(share_buf, message) {
            var ptr0 = passArray8ToWasm0(share_buf, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            wasm.partialSignBlindedMessage(8, ptr0, len0, ptr1, len1);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v2;
        };

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
        * @param {Uint8Array} share_buf
        * @param {Uint8Array} message
        * @returns {Uint8Array}
        */
        module.exports.partialSign = function(share_buf, message) {
            var ptr0 = passArray8ToWasm0(share_buf, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            wasm.partialSign(8, ptr0, len0, ptr1, len1);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v2;
        };

        /**
        * Signs the message with the provided private key without hashing and returns the signature
        *
        * # Throws
        *
        * - If signing fails
        * @param {Uint8Array} private_key_buf
        * @param {Uint8Array} message
        * @returns {Uint8Array}
        */
        module.exports.signBlindedMessage = function(private_key_buf, message) {
            var ptr0 = passArray8ToWasm0(private_key_buf, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            wasm.signBlindedMessage(8, ptr0, len0, ptr1, len1);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v2;
        };

        /**
        * Signs the message with the provided private key and returns the signature
        *
        * # Throws
        *
        * - If signing fails
        * @param {Uint8Array} private_key_buf
        * @param {Uint8Array} message
        * @returns {Uint8Array}
        */
        module.exports.sign = function(private_key_buf, message) {
            var ptr0 = passArray8ToWasm0(private_key_buf, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            wasm.sign(8, ptr0, len0, ptr1, len1);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v2;
        };

        /**
        * Verifies the signature after it has been unblinded without hashing. Users will call this on the
        * threshold signature against the full public key
        *
        * * public_key: The public key used to sign the message
        * * message: The message which was signed
        * * signature: The signature which was produced on the message
        *
        * # Throws
        *
        * - If verification fails
        * @param {Uint8Array} public_key_buf
        * @param {Uint8Array} message
        * @param {Uint8Array} signature
        */
        module.exports.verifyBlindSignature = function(public_key_buf, message, signature) {
            var ptr0 = passArray8ToWasm0(public_key_buf, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            var ptr2 = passArray8ToWasm0(signature, wasm.__wbindgen_malloc);
            var len2 = WASM_VECTOR_LEN;
            wasm.verifyBlindSignature(ptr0, len0, ptr1, len1, ptr2, len2);
        };

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
        * @param {Uint8Array} public_key_buf
        * @param {Uint8Array} message
        * @param {Uint8Array} signature
        */
        module.exports.verify = function(public_key_buf, message, signature) {
            var ptr0 = passArray8ToWasm0(public_key_buf, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            var ptr2 = passArray8ToWasm0(signature, wasm.__wbindgen_malloc);
            var len2 = WASM_VECTOR_LEN;
            wasm.verify(ptr0, len0, ptr1, len1, ptr2, len2);
        };

        /**
        * Given a blinded message and a blinding_factor used for blinding, it returns the message
        * unblinded
        *
        * * blinded_message: A message which has been blinded or a blind signature
        * * blinding_factor: The blinding_factor used to blind the message
        *
        * # Throws
        *
        * - If unblinding fails.
        * @param {Uint8Array} blinded_signature
        * @param {Uint8Array} blinding_factor_buf
        * @returns {Uint8Array}
        */
        module.exports.unblind = function(blinded_signature, blinding_factor_buf) {
            var ptr0 = passArray8ToWasm0(blinded_signature, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(blinding_factor_buf, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            wasm.unblind(8, ptr0, len0, ptr1, len1);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v2;
        };

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
        module.exports.blind = function(message, seed) {
            var ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
            var len1 = WASM_VECTOR_LEN;
            var ret = wasm.blind(ptr0, len0, ptr1, len1);
            return BlindedMessage.__wrap(ret);
        };

        /**
        * A blinded message along with the blinding_factor used to produce it
        */
        class BlindedMessage {

            static __wrap(ptr) {
                const obj = Object.create(BlindedMessage.prototype);
                obj.ptr = ptr;

                return obj;
            }

            toJSON() {
                return {
                    message: this.message,
                    blindingFactor: this.blindingFactor,
                };
            }

            toString() {
                return JSON.stringify(this);
            }

            free() {
                const ptr = this.ptr;
                this.ptr = 0;

                wasm.__wbg_blindedmessage_free(ptr);
            }
            /**
            * @returns {Uint8Array}
            */
            get message() {
                wasm.blindedmessage_message(8, this.ptr);
                var r0 = getInt32Memory0()[8 / 4 + 0];
                var r1 = getInt32Memory0()[8 / 4 + 1];
                var v0 = getArrayU8FromWasm0(r0, r1).slice();
                wasm.__wbindgen_free(r0, r1 * 1);
                return v0;
            }
            /**
            * @returns {Uint8Array}
            */
            get blindingFactor() {
                wasm.blindedmessage_blindingFactor(8, this.ptr);
                var r0 = getInt32Memory0()[8 / 4 + 0];
                var r1 = getInt32Memory0()[8 / 4 + 1];
                var v0 = getArrayU8FromWasm0(r0, r1).slice();
                wasm.__wbindgen_free(r0, r1 * 1);
                return v0;
            }
        }
        module.exports.BlindedMessage = BlindedMessage;
        /**
        * A BLS12-377 Keypair
        */
        class Keypair {

            static __wrap(ptr) {
                const obj = Object.create(Keypair.prototype);
                obj.ptr = ptr;

                return obj;
            }

            free() {
                const ptr = this.ptr;
                this.ptr = 0;

                wasm.__wbg_keypair_free(ptr);
            }
            /**
            * @returns {Uint8Array}
            */
            get privateKey() {
                wasm.keypair_privateKey(8, this.ptr);
                var r0 = getInt32Memory0()[8 / 4 + 0];
                var r1 = getInt32Memory0()[8 / 4 + 1];
                var v0 = getArrayU8FromWasm0(r0, r1).slice();
                wasm.__wbindgen_free(r0, r1 * 1);
                return v0;
            }
            /**
            * @returns {Uint8Array}
            */
            get publicKey() {
                wasm.keypair_publicKey(8, this.ptr);
                var r0 = getInt32Memory0()[8 / 4 + 0];
                var r1 = getInt32Memory0()[8 / 4 + 1];
                var v0 = getArrayU8FromWasm0(r0, r1).slice();
                wasm.__wbindgen_free(r0, r1 * 1);
                return v0;
            }
        }
        module.exports.Keypair = Keypair;
        /**
        */
        class Keys {

            static __wrap(ptr) {
                const obj = Object.create(Keys.prototype);
                obj.ptr = ptr;

                return obj;
            }

            free() {
                const ptr = this.ptr;
                this.ptr = 0;

                wasm.__wbg_keys_free(ptr);
            }
            /**
            * @param {number} index
            * @returns {Uint8Array}
            */
            getShare(index) {
                wasm.keys_getShare(8, this.ptr, index);
                var r0 = getInt32Memory0()[8 / 4 + 0];
                var r1 = getInt32Memory0()[8 / 4 + 1];
                var v0 = getArrayU8FromWasm0(r0, r1).slice();
                wasm.__wbindgen_free(r0, r1 * 1);
                return v0;
            }
            /**
            * @returns {number}
            */
            numShares() {
                var ret = wasm.keys_numShares(this.ptr);
                return ret >>> 0;
            }
            /**
            * @returns {Uint8Array}
            */
            get polynomial() {
                wasm.keys_polynomial(8, this.ptr);
                var r0 = getInt32Memory0()[8 / 4 + 0];
                var r1 = getInt32Memory0()[8 / 4 + 1];
                var v0 = getArrayU8FromWasm0(r0, r1).slice();
                wasm.__wbindgen_free(r0, r1 * 1);
                return v0;
            }
            /**
            * @returns {Uint8Array}
            */
            get thresholdPublicKey() {
                wasm.keys_thresholdPublicKey(8, this.ptr);
                var r0 = getInt32Memory0()[8 / 4 + 0];
                var r1 = getInt32Memory0()[8 / 4 + 1];
                var v0 = getArrayU8FromWasm0(r0, r1).slice();
                wasm.__wbindgen_free(r0, r1 * 1);
                return v0;
            }
            /**
            * @returns {number}
            */
            get t() {
                var ret = wasm.__wbg_get_keys_t(this.ptr);
                return ret >>> 0;
            }
            /**
            * @param {number} arg0
            */
            set t(arg0) {
                wasm.__wbg_set_keys_t(this.ptr, arg0);
            }
            /**
            * @returns {number}
            */
            get n() {
                var ret = wasm.__wbg_get_keys_n(this.ptr);
                return ret >>> 0;
            }
            /**
            * @param {number} arg0
            */
            set n(arg0) {
                wasm.__wbg_set_keys_n(this.ptr, arg0);
            }
        }
        module.exports.Keys = Keys;

        module.exports.__wbindgen_string_new = function(arg0, arg1) {
            var ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        };

        module.exports.__wbindgen_throw = function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        };

        module.exports.__wbindgen_rethrow = function(arg0) {
            throw takeObject(arg0);
        };

        module.exports.init = async function(path) {
            const wasmInstance = (await WebAssembly.instantiateStreaming(fetch(path), imports)).instance
            wasm = wasmInstance.exports;
        }

        module.exports.__wasm = wasm;

