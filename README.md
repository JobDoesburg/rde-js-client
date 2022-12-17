# RDE JS client

This repository contains the JavaScript (written in TypeScript) RDE client. It consists of mainly two parts:
- An `RDEKeyGen` library that can generate RDE keys in the browser from given enrollment parameters.
- An `RDEDecryption` library that can be used to interact with the RDE Android client app, to securely transfer decryption  
  parameters to the app and receive the reconstructed key back.

The code is written in TypeScript and compiled to JavaScript using [webpack](https://webpack.js.org/).

## Usage

### Generating RDE keys in the browser
The `RDEKeyGen` library can be used to generate a key based on RDE enrollment parameters.

```javascript
const enrollmentData = RDEKeyGen.RDEEnrollmentParameters.fromJson('...')
const keyGenerator = new RDEKeyGen.RDEKeyGenerator(enrollmentData)
rdeKey = await keyGenerator.generateKey()
const secretKey = rdeKey.secretKey
const decryptionParameters = rdeKey.decryptionParameters
```

The `RDEKey` object contains the secret key and the decryption parameters. 
The secret key can be used to encrypt data. 
The decryption parameters can be used by the holder of the RDE document to retrieve the encryption key again.

The `secretKey` should be stored in a secure way and should not be shared with anyone. 
The `decryptionParameters` can be shared with the holder of the RDE document.
They can be used to retrieve the encryption key again, via the Android client app.

### Interacting with the RDE Android client app
The `RDEDecryption` library can be used to interact with the RDE Android client app. 
It can be used to transfer the decryption parameters to the app and receive the secret key back.

The `RDEDecryptionHandshakeProtocol` object can be used to perform the handshake with the RDE Android client app.
It takes a `WebSocket` object that is used to communicate with the app.

```javascript
const socket = new WebSocket('...')
const handshake = new RDEDecryption.RDEDecryptionHandshakeProtocol(window.crypto, socket, decryptionParameters)
await handshake.performHandshake()
socket.onclose = function (event) {
    const secretKey = handshake.getSecretKey()
}
```

## Building
Use `npm run build` to build the library. The output will be in the `dist` folder. This will contain two files:
- `RDEKeyGen.js` The RDE key generation library.
- `RDEDecryption.js` The RDE decryption library.

These libraries are built with webpack and can be used in a browser environment.

## Dependencies
The RDE client library depends on the following libraries:

- [indutny/elliptic](https://github.com/indutny/elliptic) for elliptic curve operations on any curve provided by the RDE 
  document in the enrollment parameters. (According to the ICAO 9303 standard, the RDE document can use any curve, 
  which is why this library is used over the native WebCrypto API that just supports a limited number of curves, and 
  for example no Brainpool curves that are used by Dutch passports and identity cards.)
- [indutny/hash.js](https://github.com/indutny/hash.js) for hashing operations. This is also a dependency of the elliptic 
  library.
- [rosek86/aes-cmac](https://github.com/rosek86/aes-cmac) for AES CMAC operations that are required to emulate the encryption
  of an RDE document. Note that AES-CMAC is **not** used anywhere else as MAC operation. 
- [leonardodino/aes-ts](https://github.com/leonardodino/aes-ts) for AES encryption and decryption operations in CBC and ECB without 
  padding, which is required to emulate the encryption of an RDE document. Note that these modes are **not** used
  anywhere else in the library. For the decryption handshake protocol, the native WebCrypto API is used.
- [@lapo/asn1js](https://github.com/lapo-luchini/asn1js) for ASN.1 decoding operations. This is used to decode the 
  public key in the enrollment parameters.
- [@peculiar/x509](https://github.com/PeculiarVentures/x509) for verifying the signature of the enrollment parameters and certificate chain.
- [cheminfo/mrz](https://github.com/cheminfo/mrz) for parsing MRZ data.

## Face image decoding
RDE enrollment parameters can contain a facialImage.
On the documents that we have seen, this image is encoded as JP2 image.
Browsers generally do not support displaying JP2 images. 
We advise to use open source libraries to decode the image, such as [OpenJPEG](https://www.npmjs.com/package/openjpeg). 
We did not include this library in the dependencies of this project, as we do not consider displaying images in browser as a core functionality of this library, better implementations might be available, and we do not want to force users to include such libraries in their project.

An example for decoding the image using OpenJPEG is provided below, displaying the image in a canvas element.
Note that after writing the image to the canvas, it is also possible to request the base64 data url with `canvas.toDataURL()`.

```javascript
const faceImageCanvas = document.getElementById('faceImageCanvas');
const faceImageData = enrollmentData.parseFaceImage();
displayFaceImage(faceImageData, "jp2");

function displayFaceImage(imageData, imageType) {
  const rgbImage = openjpeg(imageData, imageType);
  faceImageCanvas.width = rgbImage.width;
  faceImageCanvas.height = rgbImage.height;
  const pixelsPerChannel = rgbImage.width * rgbImage.height;
  const context = faceImageCanvas.getContext('2d');
  const rgbaImage = context.createImageData(rgbImage.width, rgbImage.height);

  let i = 0, j = 0;
  while (i < rgbaImage.data.length && j < pixelsPerChannel) {
    rgbaImage.data[i] = rgbImage.data[j]; // R
    rgbaImage.data[i+1] = rgbImage.data[j + pixelsPerChannel]; // G
    rgbaImage.data[i+2] = rgbImage.data[j + 2*pixelsPerChannel]; // B
    rgbaImage.data[i+3] = 255; // A
    
    // Next pixel
    i += 4;
    j += 1;
  }
  context.putImageData(rgbaImage, 0, 0);
}
```

## Supported RDE documents
The RDE client library supports only supports documents that use AES encryption with ECDH key agreement.
It does not support documents that use RSA based DH (as most countries do not use these anymore) and/or documents that use 3DES encryption.
In order to support these documents, the `RDEKeyGenerator` should be extended to support regular DH key agreement and a different `3DESAPDUEncoder` should be implemented.

## Acknowledgements
This library is based on the [RDE Java client](https://gitlab.surf.nl/filesender/rde-java-client).
The command encoding of the AESAPDUEncoder is based on work by Stephen Kellaway for the [RDW](https://www.rdw.nl/) and the Java [JMRTD](https://jmrtd.org) library.