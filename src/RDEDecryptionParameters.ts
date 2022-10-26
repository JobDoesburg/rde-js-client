class RDEDecryptionParameters {
    constructor(readonly oid : string, readonly publicKey : string, readonly protectedCommand : string) {
        this.oid = oid;
        this.publicKey = publicKey;
        this.protectedCommand = protectedCommand;
    }

    static fromJson(json : any) : RDEDecryptionParameters {
        const data = JSON.parse(json);
        return new RDEDecryptionParameters(data.oid, data.publicKey, data.protectedCommand);
    }

}

export default RDEDecryptionParameters;