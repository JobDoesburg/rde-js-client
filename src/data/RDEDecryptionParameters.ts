/**
 * Enrollment parameters for RDE.
 */
export default class RDEDecryptionParameters {
    constructor(readonly documentName : string, readonly oid : string, readonly publicKey : string, readonly protectedCommand : string) {
        this.documentName = documentName;
        this.oid = oid;
        this.publicKey = publicKey;
        this.protectedCommand = protectedCommand;
    }

    static fromJson(json : any) : RDEDecryptionParameters {
        const data = JSON.parse(json);
        return new RDEDecryptionParameters(data.documentName, data.oid, data.publicKey, data.protectedCommand);
    }

}
