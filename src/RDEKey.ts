import RDEDecryptionParameters from "./RDEDecryptionParameters";

class RDEKey {
    constructor(readonly encryptionKey : string, readonly decryptionParameters : RDEDecryptionParameters) {
        this.encryptionKey = encryptionKey;
        this.decryptionParameters = decryptionParameters;
    }
}
export default RDEKey;