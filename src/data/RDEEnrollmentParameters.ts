import Hex from "@lapo/asn1js/hex";
import ASN1 from "@lapo/asn1js";

// @ts-ignore
import mrzParser from "mrz";
import utils from "../utils";
import PassportUtils from "../keygen/PassportUtils";
import {X509Certificate, X509Certificates, X509ChainBuilder} from "@peculiar/x509";

/**
 * Enrollment parameters for an RDE document.
 */
export default class RDEEnrollmentParameters {
    private dgHashData: string;
    private dgHashAlgorithmOID: string;
    private readonly dgHashes: string[];
    private efSODDigestData: string;
    private efSODHashAlgorithmOID: string;
    private efSODDigest: string;
    private efSODEncryptedDigest: string;
    private docSigningCertificate: X509Certificate;

    constructor(readonly documentName : string, readonly caOID : string, readonly piccPublicKey : string, readonly rdeDGId : number, readonly rdeRBLength : number, readonly rdeDGContent : string, readonly securityData : string | null, readonly mrzData : string | null, readonly faceImageData : string | null) {
        this.documentName = documentName;
        this.caOID = caOID;
        this.piccPublicKey = piccPublicKey;
        this.rdeDGId = rdeDGId;
        this.rdeRBLength = rdeRBLength;
        this.rdeDGContent = rdeDGContent;
        this.securityData = securityData;
        this.mrzData = mrzData;
        this.faceImageData = faceImageData;

        this.dgHashes = [];
        this.parseSecurityData();
    }

    static fromJson(json : any) : RDEEnrollmentParameters {
        const data = JSON.parse(json);
        return new RDEEnrollmentParameters(data.documentName, data.caOID, data.piccPublicKey, data.rdeDGId, data.rdeRBLength, data.rdeDGContent, data.securityData, data.mrzData, data.faceImageData);
    }

    private parseSecurityData() {
        if (this.securityData == null) {
            return;
        }

        const decodedData = ASN1.decode(Hex.decode(this.securityData)).sub[0].sub[1].sub[0]

        // Get the hash algorithm used to hash the data groups
        const hashingAlgorithmOIDData = decodedData.sub[1].sub[0].sub[0]
        this.dgHashAlgorithmOID = hashingAlgorithmOIDData.stream.parseOID(hashingAlgorithmOIDData.posContent(), hashingAlgorithmOIDData.posEnd(), 1000).split("\n")[0];

        // Get the hashes on the data groups
        const dgHashDataASN = decodedData.sub[2].sub[1].sub[0]
        this.dgHashData = PassportUtils.getContentFromASNStream(dgHashDataASN);
        for (let i = 0; i < dgHashDataASN.sub[0].sub[2].sub.length; i++) {
            const dgId = parseInt(dgHashDataASN.sub[0].sub[2].sub[i].sub[0].content());
            this.dgHashes[dgId] = PassportUtils.getContentFromASNStream(dgHashDataASN.sub[0].sub[2].sub[i].sub[1]);
        }

        // Get the hash algorithm used to hash the EF.SOD
        const efSODHashingAlgorithmOIDData = decodedData.sub[4].sub[0].sub[2].sub[0]
        this.efSODHashAlgorithmOID = efSODHashingAlgorithmOIDData.stream.parseOID(efSODHashingAlgorithmOIDData.posContent(), efSODHashingAlgorithmOIDData.posEnd(), 1000).split("\n")[0];

        // Get the encrypted digest of the EF.SOD
        this.efSODDigestData = PassportUtils.getContentFromASNStream(decodedData.sub[4].sub[0].sub[3])
        this.efSODDigest = PassportUtils.getContentFromASNStream(decodedData.sub[4].sub[0].sub[3].sub[1].sub[1].sub[0])
        this.efSODEncryptedDigest = PassportUtils.getContentFromASNStream(decodedData.sub[4].sub[0].sub[5])
        this.docSigningCertificate = new X509Certificate(decodedData.sub[3].sub[0].toB64String());
    }

    private async calculateHash(data : Uint8Array, hashOID = this.dgHashAlgorithmOID) : Promise<string> {
        const algName = PassportUtils.digestAlgorithmNameFromHashOID(hashOID);
        if (algName == null) {
            throw new Error("Unsupported hash algorithm");
        }
        return crypto.subtle.digest(algName, data).then((hash) => {
            return utils.toHexString(new Uint8Array(hash));
        });
    }

    async verifyRDEDGContent(): Promise<boolean> {
        if (this.dgHashes == null) {
            throw new Error("No security data present, cannot verify");
        }
        const rdeDGContent = utils.hexToBytes(this.rdeDGContent);
        const calculatedHash = await this.calculateHash(rdeDGContent);
        const mrzHash = this.dgHashes[this.rdeDGId];
        return calculatedHash == mrzHash;
    }

    async verifyMRZData(): Promise<boolean> {
        // TODO also verify expiration date
        if (this.mrzData == null) {
            throw new Error("No MRZ data present, cannot verify");
        }
        if (this.dgHashes == null) {
            throw new Error("No security data present, cannot verify");
        }
        const mrzDataBytes = utils.hexToBytes(this.mrzData);
        const calculatedHash = await this.calculateHash(mrzDataBytes);
        const mrzHash = this.dgHashes[1];
        return calculatedHash == mrzHash;
    }

    async verifyFaceImageData() : Promise<boolean> {
        if (this.faceImageData == null) {
            throw new Error("No FaceImage data present, cannot verify");
        }
        if (this.dgHashes == null) {
            throw new Error("No security data present, cannot verify");
        }
        const faceImageDataBytes = utils.hexToBytes(this.faceImageData);
        const calculatedHash = await this.calculateHash(faceImageDataBytes);
        const mrzHash = this.dgHashes[2];
        return calculatedHash == mrzHash;
    }

    async verifySecurityData(certificateMasterList : [] = []): Promise<boolean> {
        // Verify if the data in the efSOD matches the full hash on the efSOD
        const calculatedEFSODHash = await this.calculateHash(utils.hexToBytes(this.dgHashData), this.efSODHashAlgorithmOID);
        const efSODHash = this.efSODDigest;
        const efSODIntegrityResult = (calculatedEFSODHash == efSODHash);
        if (!efSODIntegrityResult) {
            console.error("EF.SOD integrity check failed");
        }

        // Verify if the efSOD is signed by the document signing certificate
        const docSigningKey = await this.docSigningCertificate.publicKey.export()
        const efSODSignedResult = await crypto.subtle.verify(this.docSigningCertificate.signatureAlgorithm, docSigningKey, utils.hexToBytes(this.efSODEncryptedDigest), utils.hexToBytes("3148" + this.efSODDigestData));
        if (!efSODSignedResult) {
            console.error("EF.SOD signature check failed");
        }

        let certificateChainResult;

        // Verify if the certificate chain for the document signing certificate is valid
        if (certificateMasterList.length == 0) {
            console.warn("No certificate master list present, cannot verify certificate chain");
            certificateChainResult = true;
        } else {
            const chainBuilder = new X509ChainBuilder({
                certificates: certificateMasterList,
            });
            const certificateChain = await chainBuilder.build(this.docSigningCertificate)
            certificateChainResult = certificateChain.length > 1;
            if (!certificateChainResult) {
                console.error("Certificate chain verification failed");
            }
        }
        return efSODIntegrityResult && efSODSignedResult && certificateChainResult;
    }


    async verify(certificateMasterList: [] = []): Promise<boolean> {
        // TODO add date parameter to allow for verification of expired passports
        if (this.securityData == null) {
            throw new Error("No security data present, cannot verify");
        }

        const securityDataResult = await this.verifySecurityData(certificateMasterList);
        if (!securityDataResult) {
            console.error("Security data verification failed");
        }

        // Verify if the RDE DG content matches the hash in the efSOD
        const rdeDGResult = await this.verifyRDEDGContent();
        if (!rdeDGResult) {
            console.error("RDE DG content verification failed");
        }

        // If mrzData is present, verify if the MRZ data matches the hash in the efSOD
        let mrzResult;
        if (this.mrzData != null) {
            mrzResult = await this.verifyMRZData();
            if (!mrzResult) {
                console.error("MRZ data verification failed");
            }
        } else {
            mrzResult = true;
        }

        // If faceImageData is present, verify if the face image data matches the hash in the efSOD
        let faceImageResult;
        if (this.faceImageData != null) {
            faceImageResult = await this.verifyFaceImageData();
            if (!faceImageResult) {
                console.error("Face image data verification failed");
            }
        } else {
            faceImageResult = true;
        }

        return securityDataResult && rdeDGResult && mrzResult && faceImageResult;
    }

    parseMRZData() : JSON {
        if (this.mrzData == null) {
            throw new Error("No MRZ data present, cannot parse");
        }

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

    parseFaceImage() : string {
        if (this.faceImageData == null) {
            throw new Error("No face image data present, cannot parse");
        }
        return ""; // TODO implement this
    }
}
