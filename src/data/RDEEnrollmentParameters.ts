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
    private dgHashes: string[];
    private dgHashAlgorithmOID: string;
    private efSODHashAlgorithmOID: string;
    private docSigningCertificate: X509Certificate;
    private dgHashData: string;
    private efSODencryptedDigest: string;
    private efSODDigest: string;
    private efSODDigestData: string;

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

        this.dgHashData = null;
        this.dgHashes = [];
        this.dgHashAlgorithmOID = "";
        this.docSigningCertificate = null;
        this.efSODencryptedDigest = null;
        this.efSODDigest = null
        this.efSODDigestData = null
        this.parseSecurityData();
    }

    static fromJson(json : any) : RDEEnrollmentParameters {
        const data = JSON.parse(json);
        return new RDEEnrollmentParameters(data.documentName, data.caOid, data.piccPublicKey, data.rdeDGId, data.rdeRBLength, data.rdeDGContent, data.securityData, data.mrzData, data.faceImageData);
    }

    private parseSecurityData() {
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
        this.efSODencryptedDigest = PassportUtils.getContentFromASNStream(decodedData.sub[4].sub[0].sub[5])
        this.docSigningCertificate = new X509Certificate(decodedData.sub[3].sub[0].toB64String());
    }

    private async calculateHash(data : Uint8Array, hashOID = this.dgHashAlgorithmOID) : Promise<string> {
        const algName = PassportUtils.digestAlgorithmNameFromHashOID(hashOID);
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
        if (this.mrzData == null) {
            throw new Error("No MRZ data present, cannot verify");
        }
        if (this.dgHashes == null) {
            throw new Error("No security data present, cannot verify");
        }
        const mrzDataBytes = utils.hexToBytes(this.mrzData);
        const calculatedHash = await this.calculateHash(mrzDataBytes);
        const mrzHash = this.dgHashes[1];
        return calculatedHash == mrzHash; // TODO this is not the correct data, we need the full data group contents, not only the first bytes
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
        return calculatedHash == mrzHash; // TODO this is not the correct data
    }

    private async verifyCertificateChain(certificates: X509Certificates, date: Date = new Date()): Promise<boolean> {
        for (let i = 0; i < certificates.length; i++) {
            const cert = certificates[i]
            if (i === 0) {
                const firstCertShouldBeDocSigningCert = (cert == this.docSigningCertificate)
                if (!firstCertShouldBeDocSigningCert) {
                    console.error("First certificate in chain should be the document signing certificate")
                    return false
                }
            }
            if (i < certificates.length - 1) {
                const signingCert = certificates[i + 1]
                const certVerifies = await cert.verify({publicKey: signingCert.publicKey, date: date})
                if (!certVerifies) {
                    console.error("Certificate chain verification failed")
                    return false
                }
            } else {
                const certIsSelfSigned = await cert.isSelfSigned()
                if (!certIsSelfSigned) {
                    console.error("Last certificate in chain should be self-signed")
                    return false
                }
            }
        }
        return true
    }

    async verifySecurityData(): Promise<boolean> {
        // Verify if the data in the efSOD matches the full hash on the efSOD
        const calculatedEFSODHash = await this.calculateHash(utils.hexToBytes(this.dgHashData), this.efSODHashAlgorithmOID);
        const efSODHash = this.efSODDigest;
        const efSODIntegrityResult = (calculatedEFSODHash == efSODHash);
        if (!efSODIntegrityResult) {
            console.error("EF.SOD integrity check failed");
        }

        // Verify if the efSOD is signed by the document signing certificate
        const docSigningKey = await this.docSigningCertificate.publicKey.export()
        const efSODSignedResult = await crypto.subtle.verify(this.docSigningCertificate.signatureAlgorithm, docSigningKey, utils.hexToBytes(this.efSODencryptedDigest), utils.hexToBytes("3148" + this.efSODDigestData));
        if (!efSODSignedResult) {
            console.error("EF.SOD signature check failed");
        }

        // Verify if the certificate chain for the document signing certificate is valid
        const chainBuilder = new X509ChainBuilder({
            certificates: this.getCertificateMasterList(),
        });
        const certificateChain = await chainBuilder.build(this.docSigningCertificate)
        const certificateChainResult = await this.verifyCertificateChain(certificateChain)
        if (!certificateChainResult) {
            console.error("Certificate chain verification failed");
        }

        return efSODIntegrityResult && efSODSignedResult && certificateChainResult;
    }


    async verify(): Promise<boolean> {
        if (this.securityData == null) {
            throw new Error("No security data present, cannot verify");
        }

        const securityDataResult = await this.verifySecurityData();
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

    getCertificateMasterList() : X509Certificate[] {
        const pk1data = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGTTCCBDWgAwIBAgICBSAwDQYJKoZIhvcNAQELBQAwaTEQMA4GA1UEAwwHQ1ND\n" +
            "QSBOTDEjMCEGA1UECwwaS2luZ2RvbSBvZiB0aGUgTmV0aGVybGFuZHMxIzAhBgNV\n" +
            "BAoMGktpbmdkb20gb2YgdGhlIE5ldGhlcmxhbmRzMQswCQYDVQQGEwJOTDAeFw0x\n" +
            "ODA2MjEwMDAwMDBaFw0zMTA2MzAwMDAwMDBaMGkxEDAOBgNVBAMMB0NTQ0EgTkwx\n" +
            "IzAhBgNVBAsMGktpbmdkb20gb2YgdGhlIE5ldGhlcmxhbmRzMSMwIQYDVQQKDBpL\n" +
            "aW5nZG9tIG9mIHRoZSBOZXRoZXJsYW5kczELMAkGA1UEBhMCTkwwggIiMA0GCSqG\n" +
            "SIb3DQEBAQUAA4ICDwAwggIKAoICAQDKO5GAXJoFLIZMUxT6zP1F/JPsEAcQDbt0\n" +
            "o74U1TUB9UuJqXzaUGbxrUXuQqgUWFKWuIU1AEfFdnYXGZYBqojWdNhoydvra4RX\n" +
            "2cdaA7Hwxmcv+jD4TpsRDrdSDkgMAx2AOgqyt8oACwFPsG04rPjx2ZBZmLGUVM35\n" +
            "kTT/XMFoPsmbc1YTnn2BhK4SXwdqSYyh/B0jt1PC91vMZEyblg/bJD8Kvl0nZkc0\n" +
            "GzQHsvlg8L7BmZKLcjmU4JkrNYCj/Us78L/jbsvGzzTaY2ienjqb/ljP0zHsfIIc\n" +
            "jWeNERps6DwKfqVt/dmnm/3V9luqB7JE6nFD6wblESMHePyOuwB5t2EHFJbg7XPO\n" +
            "WW6qt7iL4kkM4IxOK4Jn7C/mS9f0edfbdj30GifrPrg1xX/3g6JNYqgD8/kfxVFf\n" +
            "mzSNZiaOX4OBsClbJDDSMNr3OVHnGtVnKVqJ48IMOI6XnGXEUSZF1q5mN3nz9pId\n" +
            "s7t+b9y2xNQ0Q8EgL+xo5u6Nliu3m2DjPWr+HkTAaJqKsVFmAVxAhhRRdLDHiY9y\n" +
            "5bErH9Bp3nzGJF7ENK/jyzCuwpUwVHMW8Uz44FPP7QnPIsV9hcpzwvXgSdP6oGb9\n" +
            "+ZO97w/pcDI6Y/I1QzWKZQkMWOhzJtl1UilH6d4e7UDgzvK2dLRjY7xqNHBehbZh\n" +
            "qzM9HizquQIDAQABo4H+MIH7MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/\n" +
            "BAQDAgEGMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwubnBrZC5ubC9DUkxz\n" +
            "L05MRC5jcmwwGwYDVR0SBBQwEqQQMA4xDDAKBgNVBAcMA05MRDAbBgNVHREEFDAS\n" +
            "pBAwDjEMMAoGA1UEBwwDTkxEMBEGA1UdIAQKMAgwBgYEVR0gADArBgNVHRAEJDAi\n" +
            "gA8yMDE4MDYyMTAwMDAwMFqBDzIwMjEwNjIxMDAwMDAwWjApBgNVHQ4EIgQgOOPL\n" +
            "MWVyc2YMT3M0FcGAOuvYwfOQvjyx/fniMU2r+3EwDQYJKoZIhvcNAQELBQADggIB\n" +
            "AEnWXxmaKjjwXtnWbODvWiV6amfZcy9EKouFtdNvDkJO4QtcpzYrCdVLEPOj9Q6q\n" +
            "aS7nQbrZJr/FMT9ZDlf3bYbuSutMT/R8LgqZfbgMOSQDFBa5BTIrnq4kvWB/7tjz\n" +
            "+s2iiB5NrIKbHmqQSyvMsVZwKfh6m2W5ev7Fyms52KILmayApK2MOxp7pgzhjGoJ\n" +
            "taaWgxpoWs/QV9+TCs81eRjcaN7BDNGSlZvgmIBTeMCJeoFVRxAhdtSqTcbA5j8r\n" +
            "juTSerVXPGm0uZ3fqzxpz7z9LqdDxKO3ZRuFOmsjY/DedPwD+/s9pMjAzrYcYQEG\n" +
            "d24/G+ZdmuI4vbfow8Uywqpm2bK7UJizKRp6KZpF/SabbbTMd02tJlZ+BAJBg3A+\n" +
            "Q0F+jErdg4oMUjy3Z/VCFlWbih7zaWQ3RQtuzu5yTHFyYZUbvymi7BUPZt7t8kwI\n" +
            "TOx6AaHZVf98zMfOf5lsANA25oKZzxPMQl/pRBgfcKaXi4GCohF3MVZ79z9MdnVI\n" +
            "ICf5Ebe0ZozjxObJdqt7DoorLB0k9xDEkHSpPvR2V5BA1kEVBib7t8Pmxsvc2b0s\n" +
            "H+IbgKzOMnC3axoCBYzmCj1S1b4ZZ/Uh46R8VFROCpKYucrYI5Xliy77tma/94X0\n" +
            "dAIGtEsbeJ5S1kbl4rH4Fhi3rtS1U4ubvhxpsSgEez7+\n" +
            "-----END CERTIFICATE-----\n";
        const pk2data = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGqjCCBJKgAwIBAgICBSEwDQYJKoZIhvcNAQELBQAwgYcxCjAIBgNVBAUTATUx\n" +
            "EDAOBgNVBAMMB0NTQ0EgTkwxNzA1BgNVBAsMLk1pbmlzdHJ5IG9mIHRoZSBJbnRl\n" +
            "cmlvciBhbmQgS2luZ2RvbSBSZWxhdGlvbnMxITAfBgNVBAoMGFN0YXRlIG9mIHRo\n" +
            "ZSBOZXRoZXJsYW5kczELMAkGA1UEBhMCTkwwHhcNMTgwNDI0MDg1MDE0WhcNMzAw\n" +
            "MzAyMDAwMDAwWjBpMRAwDgYDVQQDDAdDU0NBIE5MMSMwIQYDVQQLDBpLaW5nZG9t\n" +
            "IG9mIHRoZSBOZXRoZXJsYW5kczEjMCEGA1UECgwaS2luZ2RvbSBvZiB0aGUgTmV0\n" +
            "aGVybGFuZHMxCzAJBgNVBAYTAk5MMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\n" +
            "CgKCAgEAyjuRgFyaBSyGTFMU+sz9RfyT7BAHEA27dKO+FNU1AfVLial82lBm8a1F\n" +
            "7kKoFFhSlriFNQBHxXZ2FxmWAaqI1nTYaMnb62uEV9nHWgOx8MZnL/ow+E6bEQ63\n" +
            "Ug5IDAMdgDoKsrfKAAsBT7BtOKz48dmQWZixlFTN+ZE0/1zBaD7Jm3NWE559gYSu\n" +
            "El8HakmMofwdI7dTwvdbzGRMm5YP2yQ/Cr5dJ2ZHNBs0B7L5YPC+wZmSi3I5lOCZ\n" +
            "KzWAo/1LO/C/427Lxs802mNonp46m/5Yz9Mx7HyCHI1njREabOg8Cn6lbf3Zp5v9\n" +
            "1fZbqgeyROpxQ+sG5REjB3j8jrsAebdhBxSW4O1zzlluqre4i+JJDOCMTiuCZ+wv\n" +
            "5kvX9HnX23Y99Bon6z64NcV/94OiTWKoA/P5H8VRX5s0jWYmjl+DgbApWyQw0jDa\n" +
            "9zlR5xrVZylaiePCDDiOl5xlxFEmRdauZjd58/aSHbO7fm/ctsTUNEPBIC/saObu\n" +
            "jZYrt5tg4z1q/h5EwGiairFRZgFcQIYUUXSwx4mPcuWxKx/Qad58xiRexDSv48sw\n" +
            "rsKVMFRzFvFM+OBTz+0JzyLFfYXKc8L14EnT+qBm/fmTve8P6XAyOmPyNUM1imUJ\n" +
            "DFjocybZdVIpR+neHu1A4M7ytnS0Y2O8ajRwXoW2YaszPR4s6rkCAwEAAaOCATsw\n" +
            "ggE3MCkGA1UdDgQiBCA448sxZXJzZgxPczQVwYA669jB85C+PLH9+eIxTav7cTAr\n" +
            "BgNVHRAEJDAigA8yMDE4MDYyMTAwMDAwMFqBDzIwMjEwNjIxMDAwMDAwWjARBgNV\n" +
            "HSAECjAIMAYGBFUdIAAwGwYDVR0RBBQwEqQQMA4xDDAKBgNVBAcMA05MRDAbBgNV\n" +
            "HRIEFDASpBAwDjEMMAoGA1UEBwwDTkxEMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6\n" +
            "Ly9jcmwubnBrZC5ubC9DUkxzL05MRC5jcmwwDgYDVR0PAQH/BAQDAgEGMBIGA1Ud\n" +
            "EwEB/wQIMAYBAf8CAQAwKwYDVR0jBCQwIoAgGADA687i5eO/LxUPdaW2JF1UmXB4\n" +
            "hkluKvLON4UOLTAwDQYHZ4EIAQEGAQQCBQAwDQYJKoZIhvcNAQELBQADggIBAAIX\n" +
            "yyNYnYfeK+ZDDJkgddQXnm09lPBOfFp1c5Cb5xLWe/O/U4uc35JBNZ2V5biom3Qx\n" +
            "vjuXmBAA4bGmZSYsntcVXm/WQAl03YEZX3BFdPkB8JATMvUXsrzepnL+sG4c/Cn5\n" +
            "kMzBjViuql6ctJ838eVlFSCG/325hx6ZmbtNM1a5rQ8a3cvSzOW4/Lg51cuKc1KC\n" +
            "4B39R4FIxyg6Fzoh/fdJMQb4SO14pCJhUkuJQ2bJK6lbMST79Pa4ZsB1I9jiPaJ3\n" +
            "1Qq+8yCgzNReuuLXJGz+KE5CpHG83ZdyZ/qO2dzTGEcnciovoO5xNCQnU4AVbc3Y\n" +
            "O7c+AsaLx6lSn/1EFDPoQmGNiAZwqloshXhzhXERHRnbRttaL0PCvlaRRHNt61ld\n" +
            "nP6HjzZg125ozi4759o6PfHjOzDrViK67s6aAhIaDxswBdtndcONui8qjDbPcjeo\n" +
            "Db1rqoM5bOR6wlc750yIhvOepYqiBTqZYh6YWrpsQ1U7n4pja8mF1PQsN+GX8EQs\n" +
            "TZ889qt02zMUAgjkJfhpmXB1Uw+HywinoVrnayinLKKiIQ3/yXT+2V4PfLJ3eaIS\n" +
            "Kd6HNJ/QRjP3Ktn/qHeEup3LK9HVJQKHVceUmja1nKoWxnOGzlaVK/7I7KeERlxS\n" +
            "Ob4fUkDshCiARqa7bJGZKlMf0hT0JR+D8jPDYiAn\n" +
            "-----END CERTIFICATE-----\n";
        const pk3data = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGlzCCBH+gAwIBAgICB6UwDQYJKoZIhvcNAQELBQAwaTEQMA4GA1UEAwwHQ1ND\n" +
            "QSBOTDEjMCEGA1UECwwaS2luZ2RvbSBvZiB0aGUgTmV0aGVybGFuZHMxIzAhBgNV\n" +
            "BAoMGktpbmdkb20gb2YgdGhlIE5ldGhlcmxhbmRzMQswCQYDVQQGEwJOTDAeFw0y\n" +
            "MTAzMDgxMDQ3MDFaFw0zMTA2MzAwMDAwMDBaMHUxCjAIBgNVBAUTATYxEDAOBgNV\n" +
            "BAMMB0NTQ0EgTkwxIzAhBgNVBAsMGktpbmdkb20gb2YgdGhlIE5ldGhlcmxhbmRz\n" +
            "MSMwIQYDVQQKDBpLaW5nZG9tIG9mIHRoZSBOZXRoZXJsYW5kczELMAkGA1UEBhMC\n" +
            "TkwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDtuSbB2oCMiwFNrdzi\n" +
            "RP+ItiKR3VLbwJGKGbGbiCySzcHPR5lmoTT48LsxlJ6AxQ0F8lMwBMMxEVwC8I3v\n" +
            "Cg+utRcTqmp3bE4m7ny6xot2i/rkXCSvwqBG3lc7tGM8Hy/sYL96rPYomCGu9l3K\n" +
            "ToHQrRpyAOHECPSJuHBrceShI7vJZGADF8H1w5WSV/D8ghfjOGYpGYdGIqjkS+wi\n" +
            "oQIK4ESCoWvCjW+SL+J9ZHcccJkSwU+IjEVCY4roDI9s102WjDwFWL9nPYjQtAdh\n" +
            "L7i91I7Msz8jdd4xKYL6m/3iglg3H97XYthfKnhH/M5ax9FgGWQ7rhpMsnvZaQ2/\n" +
            "0fY5PTWXrcmWKhjqgpW9bSX+wRITSk4r9hDTvPFFkh7blovjMLQCLnW0kLPePzOc\n" +
            "dEp/5nbDlijMVT77fDj/o7OV8v9QCYY3L0doHE8HPRksR2hO1Ub7d8EyYq1F+KBb\n" +
            "p86Qtn/KKMTUc0n7NcJMR4516YMW1p03UkHd0TGZv4mmP+idJhOhp9empshf3boc\n" +
            "WXhhfFXotdwqNfDBi557mnVqAQ76HcJpWmE+5HlUNnNo6sZSY6GSAJntsGEOlNY4\n" +
            "b1EmnF7Ebr+FMgLYPFgY4W5vs5dEQMkjEVrBXu7ceX5LWBmFL0mPcf2xZergMg0I\n" +
            "Dtdd4jUVnFhl3GuoOzu4waevswIDAQABo4IBOzCCATcwKQYDVR0OBCIEIFTf4pYc\n" +
            "bPRj3wgffHB9ppkAJOabWkJ3BUGryS/slaWgMCsGA1UdEAQkMCKADzIwMjEwNjIx\n" +
            "MDAwMDAwWoEPMjAyNDA2MjEwMDAwMDBaMBEGA1UdIAQKMAgwBgYEVR0gADAbBgNV\n" +
            "HREEFDASpBAwDjEMMAoGA1UEBwwDTkxEMBsGA1UdEgQUMBKkEDAOMQwwCgYDVQQH\n" +
            "DANOTEQwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL2NybC5ucGtkLm5sL0NSTHMv\n" +
            "TkxELmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADArBgNV\n" +
            "HSMEJDAigCA448sxZXJzZgxPczQVwYA669jB85C+PLH9+eIxTav7cTANBgdngQgB\n" +
            "AQYBBAIFADANBgkqhkiG9w0BAQsFAAOCAgEAiv+HVLOGYPOY8yDWEzdVvhfLBRc9\n" +
            "Uv7KSPn5tNbsYEGxEXbsZ8f2d8MGB+m2oeI+YAPR99ikUoCiUT/Ua0qCyGo2tE7W\n" +
            "ihyGvIKbS2J/w98xsceyjZfl0gUe+95kjj36j5R0mpAeE8CGCIBLwi25ZTUFGSyc\n" +
            "naJSiWJ/4vvXLW6nAzMxyRqO1zzKt7p3ZEtY1KCwjUzbhpA6Gvj5mckxxAhfIwB1\n" +
            "PYSbmWCzmmr74nC93K5NZT//9PwY6De6DBMVp77bPw/2nOYyZq5O1ebl/52Gwohc\n" +
            "l/g5fRVYRdHxmmFy/052Bo8pbyXksjSpYjZqbjcz8uWea2nuFYODJeI39j0tOLny\n" +
            "0e1DEO4Vxw+Hj31Q+sIJswekZZ6LvbVQi6lbMG317j9+Lmrz0HQfW0W5HIS3rNan\n" +
            "V7lUZOjiQbOtcoGBTpvlK6u/aE/1TZ+XBx4dIa+seGFhj/FJyz023jnltJaj6XmS\n" +
            "QP63Kc0WkzChMQVTnoYNmwO3KXFkWugj5yOY9fb8G2vvKd7alCu74h8lHk0KQEjJ\n" +
            "n9AL9MHOl5TlKvQO97YfRN06xyrYj92Ovfx4F2eIFBWKVDDvC57cPaKUv51e09IY\n" +
            "L5mX0gKV/S0yy+a93SS8kdK0NLnZgQVdqGQ/sGOW5HA4MJMwUyr1RG4HEwUFtKCZ\n" +
            "WOH7wwN5JOFoV8o=\n" +
            "-----END CERTIFICATE-----\n";

        const pk1 = new X509Certificate(pk1data)
        const pk2 = new X509Certificate(pk2data)
        const pk3 = new X509Certificate(pk3data)

        return [pk1, pk2, pk3]
    }
}
