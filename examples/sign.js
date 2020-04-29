// Simple Example of blinding, signing, unblinding and verifying.

// Import the library
const threshold = require("../src/blind_threshold_bls")
const crypto = require('crypto')

// Get a message and a secret for the user
const msg = Buffer.from("hello world")

// Generate a keypair for the service
const service_seed = crypto.randomBytes(32)
const keypair = threshold.keygen(service_seed)
const private_key = keypair.privateKey
const public_key = keypair.publicKey

// Sign the user's message with the service's private key
const sig = threshold.sign(private_key, msg)

// User verifies the signature
threshold.verify(public_key, msg, sig)
console.log("Verification successful")
