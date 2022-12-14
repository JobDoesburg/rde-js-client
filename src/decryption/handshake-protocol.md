# RDE decryption handshake protocol
This document describes the RDE decryption handshake protocol. 
This protocol is used to transfer the decryption parameters to the RDE Android client app and receive the secret key back in a secure way. 
The protocol is based on a simple ECDH key agreement protocol with AES-CBC message encryption.

## Overview
1. The app generates an ephemeral EC key pair and sends the public key to the browser.
2. The browser generates an ephemeral EC key pair and a random AES IV value, and sends the public key and IV the app.
3. Both the browser and the app calculate the shared secret using the private key and the public key received from the 
   other party.
4. The browser encrypts the decryption parameters using AES-CBC with the shared secret as key and the IV and sends the 
   encrypted data to the app.
5. The app decrypts the data and initiates decryption within the app.
6. The app encrypts the retrieved secret key using AES-CBC and sends it to the browser.

## Protocol
A typical protocol flow from the app's perspective is provided below.
```
<<< {"kty":"EC","crv":"P-384","x":"6Xkm00QeqHDBx6s87DTj4hekvqa83JUTV94m6Dnu2b89lgc1KKnv_8bA2cvBpM_5","y":"2329noJUz1_oT-MwGsPWFuCUWtWmnidmW9M6plGBTi02OIUGB9Cz2F3IzQMD0Fyi"}
>>> {"key":{"crv":"P-384","ext":true,"key_ops":[],"kty":"EC","x":"sRKBzdyM2mbk6_XOlKby-Cox85FXwGN-Fc4FhZtawjcFQHhHrHBhj6irH6WaxMVz","y":"nzs-3-LBGqWKcg98mw6wuwGy6FLHt2CWj8BB6KoafpMOB_omA0tnPoSxya573UIT"},"iv":"deddd9bc8c0165aeb7bbb1ee15944037"}
>>> 515ca4a18ea3812a0bec54c164af851e6e5e8346edf2c1f973f201bc94550071881bd645d909e2d52a8304c2f2197ca1403465131cd55be329c0772536e4f05dbf551acf7df282123935ea66c8b4f6b69e0a91da143284d42c23df57529800792e6b01c04e3778f425062cb7896d0f3d1d843be1f0d8d71b2356e6fe34b917e54189eed18e3216b1c48f491edea79a1cac328e51e299aae65c57357027b3e0d0b6048c8c795e7ff16e708af76d0ee1d35c584ee68b787030abbbd9f829faa1b80ee7ea2d27399af957c8d8a8df0a2c8afe25ff0dc6b5b4c03e9f6b14975121249696f64248f9cb9ab7b7035cd50e04e9e2a64ee5d4478b888188302861a3d44e52373f56ee638bee3b01c9e651423fb0689c63932079c178ab6f82b3c121b03f0582cdb1bf80384e1bde678294b9861c5e6258e0672eeeba3ba4f8a6f81a998e4b7fa56c12a4dcc07576067fd54551bcc1edea2bfdc865f3b809d34a743fa0ccabd7353ca747a90862cf2c114d1b29ef40b57c7b3b552dc26534d2555b785135131c65d164934aa71dd7a80392e00e312793899f54fa69d0f1cc881d8596696ed8a6166cba5abf3d726fb7c8c18de56f71324ddc23c1441ee37b36a1e60f2a52daef13d076b136b7cad8b9c8f8b3e6c1016711b1be8281d2b781bc536cc9d8cc8e5cda5c28f63612bee04cee731b6003fc112698fb1d4813694908a52da80579fc41200765923f121c219a9fcdd4dd2d77ee5181916aae13e88bcc2efd914d3e523e48869731e2c47e533f789771e6b1f05c44f3bd9c643291301afd85fa4afc83f0f0f70bd2e20002568def310c674dfb358286b07e880f271d07bf5b70e92a2344db3248eb3e85ffd83c1cfa86040bbbe77ca206d8655fc4790d735873253db0720074b4ca0b2f21700bec6100da87619a91a80bc1b14302981678f7e03f9a8efd151141e4cfd8b88305b27b1ebfe5ddc1100681520b79c55701aeefca015fea6528dd2e5f06ae2b396fa5f1dcc75290f33329c304f7915f421fcab3cd99689f94d04cbf18202f04c883d795633c417fc6889c578b4c8d40e4ae3084d46545a022cc2f76c12b16a4650c10e147b7e4370b1ff4da2709bb54e718a3f3f09127af328c7834f8ad8cae015999a3bed4795bcd0b4214a375f104e5ccc9f91e9ae361d6026cb53d2e7b660541ebab2d738731bd5ab34f8a7b56764d34de5c52a84c
<<< 228e8fb80c8d0da375028fe9cead0bc786a18dcc698d71eec836a16157fb9094243053b55effa4f5f0a9ad6f7bafdef26485c2694fdefb860ae302b8398acbdebbce7f7eb2831afdd0a2f330be35607e
```

The first message is sent by the app to the browser and contains the ephemeral public key of the app as JWK. 
The browser responds with its own ephemeral public key as JWK and an IV for the AES-CBC encryption. 
The browser then also sends the encrypted decryption parameters to the app.
The app finally responds with the encrypted retrieved key.


## Security considerations
The protocol is expected to run over secure WebSocket connections (TLS), which is why the protocol does not include any additional security measures. 
The only reason for encryption is to hide the retrieved key from the proxy server that is used to facilitate communication between the browser and the app. 
If no proxy server is used, there is no reason to implement the protocol in a secure way. 
In that case, the protocol can be simplified to just sending the decryption parameters to the app and receiving the encryption key back, without any encryption.

## Crypto
The protocol uses the following crypto primitives:
- Elliptic curve cryptography (ECC) with the NIST P-384 curve and ECDH key agreement, using the native WebCrypto API.
- AES-CBC with a 256-bit key and a 128-bit IV, using the native WebCrypto API.