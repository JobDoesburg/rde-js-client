import DecryptionParameters from "./RDEDecryptionParameters";

/**
 * An RDE key.
 */
export default class RDEKey {
    constructor(readonly secretKey : Uint8Array, readonly decryptionParameters : DecryptionParameters) {
        this.secretKey = secretKey;
        this.decryptionParameters = decryptionParameters;
    }
}
