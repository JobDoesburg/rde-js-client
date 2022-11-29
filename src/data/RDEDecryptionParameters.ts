/**
 * Enrollment parameters for RDE.
 */
export default class RDEDecryptionParameters {
    constructor(readonly documentName : string, readonly caOID : string, readonly pcdPublicKey : string, readonly protectedCommand : string) {
        this.documentName = documentName;
        this.caOID = caOID;
        this.pcdPublicKey = pcdPublicKey;
        this.protectedCommand = protectedCommand;
    }

    static fromJson(json : any) : RDEDecryptionParameters {
        const data = JSON.parse(json);
        return new RDEDecryptionParameters(data.documentName, data.caOID, data.pcdPublicKey, data.protectedCommand);
    }

}
