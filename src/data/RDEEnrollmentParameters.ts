import Hex from "@lapo/asn1js/hex";
import ASN1 from "@lapo/asn1js";

// @ts-ignore
import mrzParser from "mrz";
import utils from "../utils";
import PassportUtils from "../keygen/PassportUtils";
import {X509Certificate} from "@peculiar/x509";

/**
 * Enrollment parameters for an RDE document.
 */
export default class RDEEnrollmentParameters {
    private dgHashes: string[];
    private dgHashAlgorithmOID: string;
    private efSODHashAlgorithmOID: string;
    private docSigningCertificate: X509Certificate;
    private dgHashDataBytes: string;
    private efSODencryptedDigest: string;
    private efSODDigest: string;

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

        this.dgHashDataBytes = null;
        this.dgHashes = [];
        this.dgHashAlgorithmOID = "";
        this.docSigningCertificate = null;
        this.efSODencryptedDigest = null;
        this.efSODDigest = null
        this.parseSecurityData();
    }

    static fromJson(json : any) : RDEEnrollmentParameters {
        const data = JSON.parse(json);
        return new RDEEnrollmentParameters(data.documentName, data.caOid, data.piccPublicKey, data.rdeDGId, data.rdeRBLength, data.rdeDGContent, data.securityData, data.mrzData, data.faceImageData);
    }

    private async calculateHash(data : Uint8Array, hashOID = this.dgHashAlgorithmOID) : Promise<string> {
        const algName = PassportUtils.digestAlgorithmNameFromHashOID(hashOID);
        return crypto.subtle.digest(algName, data).then((hash) => {
            return utils.toHexString(new Uint8Array(hash));
        });
    }

    private async verifyRDEDGContent(): Promise<boolean> {
        const rdeDGContent = utils.hexToBytes(this.rdeDGContent);
        const calculatedHash = await this.calculateHash(rdeDGContent);
        const mrzHash = this.dgHashes[this.rdeDGId];
        return calculatedHash == mrzHash;
    }


    private async verifyMRZData(): Promise<boolean> {
        if (this.mrzData == null) {
            throw new Error("No MRZ data present, cannot verify");
        }
        const mrzDataBytes = utils.hexToBytes(this.mrzData);
        const calculatedHash = await this.calculateHash(mrzDataBytes);
        const mrzHash = this.dgHashes[1];
        return calculatedHash == mrzHash; // TODO this is not the correct data, we need the full data group contents, not only the first bytes
    }

    private async verifyFaceImageData() : Promise<boolean> {
        if (this.faceImageData == null) {
            throw new Error("No FaceImage data present, cannot verify");
        }
        const faceImageDataBytes = utils.hexToBytes(this.faceImageData);
        const calculatedHash = await this.calculateHash(faceImageDataBytes);
        const mrzHash = this.dgHashes[2];
        return calculatedHash == mrzHash; // TODO this is not the correct data
    }

    private parseSecurityData() : any {
        const decodedData = ASN1.decode(Hex.decode(this.securityData)).sub[0].sub[1].sub[0]
        const hashingAlgorithmOIDData = decodedData.sub[1].sub[0].sub[0]
        this.dgHashAlgorithmOID = hashingAlgorithmOIDData.stream.parseOID(hashingAlgorithmOIDData.posContent(), hashingAlgorithmOIDData.posEnd(), 1000).split("\n")[0];
        const dgHashData = decodedData.sub[2].sub[1].sub[0]
        this.dgHashDataBytes = PassportUtils.getContentFromASNStream(dgHashData);

        for (let i = 0; i < dgHashData.sub[0].sub[2].sub.length; i++) {
            const dgId = parseInt(dgHashData.sub[0].sub[2].sub[i].sub[0].content());
            this.dgHashes[dgId] = PassportUtils.getContentFromASNStream(dgHashData.sub[0].sub[2].sub[i].sub[1]);
        }

        // TODO get full hash of efSOD
        const efSODHashingAlgorithmOIDData = decodedData.sub[4].sub[0].sub[2].sub[0]
        this.efSODHashAlgorithmOID = efSODHashingAlgorithmOIDData.stream.parseOID(efSODHashingAlgorithmOIDData.posContent(), efSODHashingAlgorithmOIDData.posEnd(), 1000).split("\n")[0];
        console.log("efSODHashingAlgorithmOIDData", efSODHashingAlgorithmOIDData)

        console.log("Signature digest alg", decodedData.sub[4].sub[0].sub[2].toHexString())
        console.log("Signed data", decodedData.sub[4].sub[0].sub[3].toHexString())
        console.log("Should equal mRTDSignatureData oid", decodedData.sub[4].sub[0].sub[3].sub[0].sub[1].sub[0].toHexString())


        this.efSODDigest = PassportUtils.getContentFromASNStream(decodedData.sub[4].sub[0].sub[3])
        console.log("efSODDigest", this.efSODDigest)

        this.dgHashes[0] = PassportUtils.getContentFromASNStream(decodedData.sub[4].sub[0].sub[3].sub[1].sub[1].sub[0])
        console.log("Given hash of efSOD", this.dgHashes[0])

        const base64Cert = decodedData.sub[3].sub[0].toB64String()
        this.docSigningCertificate = new X509Certificate(base64Cert);
        console.log("docSigningCertificate", this.docSigningCertificate);
        console.log("docSigningCertificate public key data", utils.toHexString(new Uint8Array(this.docSigningCertificate.publicKey.rawData)));
        console.log("Signing key", decodedData.sub[4].toHexString())
        this.efSODencryptedDigest = PassportUtils.getContentFromASNStream(decodedData.sub[4].sub[0].sub[5])
        console.log("efSODencryptedDigest", this.efSODencryptedDigest)
        this.efSODDigest = PassportUtils.getContentFromASNStream(decodedData.sub[4].sub[0].sub[3])
        console.log("efSODDigest", this.efSODDigest)
    }

    async verifySecurityData(): Promise<boolean> {
        if (this.securityData == null) {
            throw new Error("No security data present, cannot verify");
        }

        // Compute hash of rdeDGContent
        // Get hash of rdeDGId from securityData
        const rdeDGResult = await this.verifyRDEDGContent();
        console.log("RDE DG content verification result: ", rdeDGResult);


        // If mrzData:
        if (this.mrzData != null) {
            const mrzResult = await this.verifyMRZData();
            console.log("MRZ data verification result: ", mrzResult);
        }

        // If faceImageData:
        if (this.faceImageData != null) {
            const faceImageResult = await this.verifyFaceImageData();
            console.log("Face image data verification result: ", faceImageResult);
        }

        // Verify hash on efSOD
        console.log("dgHashDataBytes", this.dgHashDataBytes)
        const calculatedEFSODHash = await this.calculateHash(utils.hexToBytes(this.dgHashDataBytes), this.efSODHashAlgorithmOID);
        const efSODHash = this.dgHashes[0];
        const efSODResult = (calculatedEFSODHash == efSODHash);
        console.log("EFSOD hash result: ", efSODResult);

        // Verify signature on efSOD by using the public key from the certificate
        const docSigningKey = await this.docSigningCertificate.publicKey.export()
        const result = await crypto.subtle.verify(this.docSigningCertificate.signatureAlgorithm, docSigningKey, utils.hexToBytes(this.efSODencryptedDigest), utils.hexToBytes("3148" + this.efSODDigest));
        console.log("EFSOD signature verification result", result)

        console.log("docSigningCertificate", this.docSigningCertificate.toString("pem"))


        // Verify certificate chain on public key
        // TODO not done
        const certVerifies = await this.docSigningCertificate.verify(
            {
                date: new Date(),
                publicKey: this.docSigningCertificate.publicKey,
            },
        );
        console.log("Certificate verifies", certVerifies);

        return true;
    }

    getMRZData() : JSON {
        const decodedData = ASN1.decode(Hex.decode(this.mrzData))
        const decodedMRZData = decodedData.sub[0].stream.parseStringUTF(decodedData.sub[0].posContent(), decodedData.sub[0].posEnd(), decodedData.sub[0].length).str;

        let mrzLines;
        if (decodedMRZData.length == 90) { // TD1 format
            mrzLines = [ decodedMRZData.substring(0, 30), decodedMRZData.substring(30, 60), decodedMRZData.substring(60, 90) ];
        } else if (decodedMRZData.length == 72) { // TD2 format
            mrzLines = [ decodedMRZData.substring(0, 36), decodedMRZData.substring(36, 72) ];
        } else if (decodedMRZData.length == 88) { // TD3 format
            mrzLines = [ decodedMRZData.substring(0, 44), decodedMRZData.substring(44, 88) ];
        }

        const parsedMRZData = mrzParser.parse(mrzLines)
        if (!parsedMRZData.valid) {
            throw new Error("Invalid MRZ data");
        }
        return parsedMRZData;
    }

    getFaceImageData() : string {
        // Parse face image data and output as some image
        return "";
    }

}
