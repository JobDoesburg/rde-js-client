# RDE JS client

This repository contains the Javascript RDE client. It consists of mainly two parts:
- A Javascript library that can generate RDE keys in the browser from given enrollment parameters.
- A Javascript library that can be used to interact with the RDE Android client app, to securely transfer decryption  
  parameters to the app and receive the reconstructed key back.

## Usage

### Generating RDE keys in the browser
The `RDEKeyGen` library can be use to generate a key based on enrollment parameters.

```javascript
const enrollmentData = RDEKeyGen.RDEEnrollmentParameters.fromJson(enrollmentParamsField.value)
const keyGenerator = new RDEKeyGen.RDEKeyGenerator(enrollmentData)
rdeKey = await keyGenerator.generateKey()
const encryptionKey = rdeKey.encryptionKey
const decryptionParameters = rdeKey.decryptionParameters
```

The `RDEKey` object contains the encryption key and the decryption parameters. The encryption key can be used to encrypt
data. The decryption parameters can be used by the holder of the RDE document to retrieve the encryption key again.

The `encryptionKey` should be stored in a secure way and should not be shared with anyone. The `decryptionParameters` 
can be shared with the holder of the RDE document. They can be used to retrieve the encryption key again, via the 
android client app.

### Interacting with the RDE Android client app
The `RDEDecryptiom` library can be used to interact with the RDE Android client app. It can be used to transfer the
decryption parameters to the app and receive the encryption key back.

```javascript
const socket = new WebSocket('...')
const handshake = new RDEDecryption.RDEDecryptionHandshakeProtocol(window.crypto, socket, decryptionParameters);
await handshake.performHandshake();
socket.onclose = function (event) {
    const encryptionKey = handshake.getEncryptionKey();
}
```

The `RDEDecryptionHandshakeProtocol` object can be used to perform the handshake with the RDE Android client app. It 
takes a `WebSocket` object that is used to communicate with the app.


## Building
Use `npm run build` to build the library. The output will be in the `dist` folder. This will contain two files:
- `RDEKeyGen.js` The RDE key generation library.
- `RDEDecryption.js` The RDE decryption library.

These libraries are built with webpack and can be used in a browser environment.

## Dependencies
The RDE client library depends on the following libraries:
- [elliptic](https://github.com/indutny/elliptic) for elliptic curve operations on any curve provided by the RDE 
  document in the enrollment parameters. (According to the ICAO 9303 standard, the RDE document can use any curve, 
  which is why this library is used over the native WebCrypto API that just supports a limited number of curves, and 
  for example no brainpool curves that are used by dutch passports and identity cards.)
- [hash.js](https://github.com/indutny/hash.js) for hashing operations. This is also a dependency of the elliptic 
  library.
- [aes-cmac](https://github.com/rosek86/aes-cmac) for AES CMAC operations that are required to emulate the encryption
  of an RDE document. Note that AES-CMAC is **not** used anywhere else as MAC operation. 
- [aes-ts](https://github.com/leonardodino/aes-ts) for AES encryption and decryption operations in CBC and ECB without 
  padding, which is required to emulate the encryption of an RDE document. Note that these modes are **not** used
  anywhere else in the library. For the decryption handshake protocol, the native WebCrypto API is used.
- [@lapo/asn1js](https://github.com/lapo-luchini/asn1js) for ASN.1 decoding operations. This is used to decode the 
  public key in the enrollment parameters.

## Supported RDE documents
The RDE client library supports only supports documents that use AES encryption with ECDH key agreement. It does not 
support documents that use RSA encryption or RSA key agreement (as most countries do not use these anymore). In order
to support these documents, the `RDEKeyGenerator` should be extended to support different key agreement algorithms and
a different `DESAPDUEncoder` should be implemented to support different encryption algorithms.

## Acknowledgements
This library is based on the [RDE Android client](https://gitlab.surf.nl/filesender/rde-client-android). The
command encoding of the AESAPDUEncoder is based on work by Stephen Kellaway for the [RDW](https://www.rdw.nl/).