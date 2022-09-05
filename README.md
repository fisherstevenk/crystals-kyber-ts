# CRYSTALS Kyber Typescript KEM

<p align="center">
  <img src="./kyber.jpg"/>
</p>

**KYBER** is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices.  The homepage for CRYSTALS Kyber can be found [here](https://pq-crystals.org/kyber/index.shtml) (some information from this README is pulled directly from their site).

The initial creation of this code was a mix of the Java implementation of [Kyber (version 3)](https://github.com/fisherstevenk/kyberJCE) and this Javascript implementation of [Kyber (version 3)](https://github.com/antontutoveanu/crystals-kyber-javascript).

Kyber has three different parameter sets: 512, 768, and 1024.  Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 aims at security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to AES-256.

## Integrating the Kyber KEM Library
KyberHandshake will handle all of the Kyber calls and hold all of the keys and associated cipher texts and shared secrets. 

```bash
import {Kyber1024Handshake, Kyber512Handshake, Kyber768Handshake} from "crystals-kyber-ts";
....
const bobHandshake = new Kyber1024Handshake();
   
```

## Example Use
The following code shows a basic Key Agreement between two parties.

```bash
/**
* Generate 2 key agreements, one for Bob and one for Alice
*/
const bobHandshake = new Kyber1024Handshake();
const aliceHandshake = new Kyber1024Handshake();

/**
* Send Bob's public key to Alice and generate the Cipher Text and Shared Secret
*/
const bobPublicKey: number[] = bobHandshake.publicKey;
const aliceCipherText: number[] = aliceHandshake.generateCipherTextAndSharedSecret(bobPublicKey);

/**
* Send the cipher text generated from Bob's public key to Bob so that he
* can generate the same remote shared secret
*/
const bobSharedSecret: number[] = bobHandshake.generateRemoteSharedSecret(aliceCipherText);
```

## DISCLAIMER
This library is available under the MIT License. The tests from the [Java](https://github.com/fisherstevenk/kyberJCE) implementation have been converted to Typescript.  The original test files are used as the main test source.  Additional tests include AES encoding and decoding, a key agreement, and a massively multi-threaded key agreement test for good measure. The tests all pass, however please note that the code has not been examined by a third party for potential vulnerabilities.

## Further Information
More details about CRYSTALS and the most secure ways to use it can be found [here](https://pq-crystals.org/index.shtml)

## Contact
fisherstevenk@swiftcryptollc.com
