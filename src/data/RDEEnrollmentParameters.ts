/**
 * Enrollment parameters for an RDE document.
 */
export default class RDEEnrollmentParameters {
    constructor(readonly documentName : string, readonly caOid : string, readonly piccPublicKey : string, readonly rdeDGId : number, readonly rdeRBLength : number, readonly rdeDGContent : string, readonly securityData : string | null, readonly mrzData : string | null, readonly faceImageData : string | null) {
        this.documentName = documentName;
        this.caOid = caOid;
        this.piccPublicKey = piccPublicKey;
        this.rdeDGId = rdeDGId;
        this.rdeRBLength = rdeRBLength;
        this.rdeDGContent = rdeDGContent;
        this.securityData = securityData;
        this.mrzData = mrzData;
        this.faceImageData = faceImageData;
    }

    static fromJson(json : any) : RDEEnrollmentParameters {
        const data = JSON.parse(json);
        return new RDEEnrollmentParameters(data.documentName, data.caOid, data.piccPublicKey, data.rdeDGId, data.rdeRBLength, data.rdeDGContent, data.securityData, data.mrzData, data.faceImageData);
    }

}
