/**
 * Enrollment parameters for an RDE document.
 */
export default class RDEEnrollmentParameters {
    constructor(readonly n : number, readonly Fid : number, readonly Fcont : string, readonly caOid : string, readonly piccPublicKey : string, readonly documentName : string) {
        this.n = n;
        this.Fid = Fid;
        this.Fcont = Fcont;
        this.caOid = caOid;
        this.piccPublicKey = piccPublicKey;
        this.documentName = documentName;
    }

    static fromJson(json : any) : RDEEnrollmentParameters {
        const data = JSON.parse(json);
        return new RDEEnrollmentParameters(data.n, data.Fid, data.Fcont, data.caOid, data.piccPublicKey, data.documentName);
    }

}
