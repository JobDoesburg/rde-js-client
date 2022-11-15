import DecryptionParameters from "./RDEDecryptionParameters";

/**
 * An RDE key.
 */
export default class RDEKey {
    constructor(readonly encryptionKey : string, readonly decryptionParameters : DecryptionParameters) {
        this.encryptionKey = encryptionKey;
        this.decryptionParameters = decryptionParameters;
    }
}
