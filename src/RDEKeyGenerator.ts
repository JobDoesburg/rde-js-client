import RDEEnrollmentParameters from "./RDEEnrollmentParameters";
import RDEDecryptionParameters from "./RDEDecryptionParameters";
import RDEDocument from "./RDEDocument";
import elliptic from "elliptic";
import AESAPDUEncoder from "./AESAPDUEncoder";
import RDEKey from "./RDEKey";

function toHexString(byteArray : Uint8Array) : string {
    let s = '';
    byteArray.forEach(function(byte) {
        s += ('0' + (byte & 0xFF).toString(16)).slice(-2);
    });
    return s;
}

function hexToBytes(hex : string) : Uint8Array{
    let bytes = [];
    let c = 0;
    for (; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return new Uint8Array(bytes);
}

class RDEKeyGenerator {
    private readonly oid: string;
    private readonly agreementAlg: string;
    private readonly cipherAlg: string;
    private readonly keyLength: number;
    private readonly digestAlg: Hash;

    private readonly curve: elliptic.ec;
    private piccPublicKey: elliptic.ec.KeyPair;

    constructor(readonly enrollmentParameters : RDEEnrollmentParameters) {
        this.oid = enrollmentParameters.caOid
        this.agreementAlg = RDEDocument.agreementAlgFromCAOID(this.oid)
        this.cipherAlg = RDEDocument.cipherAlgorithmFromCAOID(this.oid)
        this.keyLength = RDEDocument.keyLengthFromCAOID(this.oid)
        this.digestAlg = RDEDocument.digestAlgorithmForCipherAlgorithm(this.cipherAlg, this.keyLength)

        this.curve = RDEDocument.decodeCurve(enrollmentParameters.piccPublicKey)
        this.piccPublicKey = RDEDocument.decodePublicKey(this.curve, enrollmentParameters.piccPublicKey)
    }

    async generateKey(): Promise<RDEKey> {
        const pcdKeyPair = RDEKeyGenerator.generateKeyPair(this.curve);
        const sharedSecret = new Uint8Array(pcdKeyPair.derive(this.piccPublicKey.getPublic()).toArray())

        const encryptionKey = await this.deriveEncryptionKey(sharedSecret);
        const protectedCommand = await this.generateProtectedCommand(sharedSecret);
        const decryptionParams = new RDEDecryptionParameters(this.oid, pcdKeyPair.getPublic(false, "hex"), toHexString(protectedCommand));
        return new RDEKey(encryptionKey, decryptionParams);
    }

    async generateProtectedCommand(sharedSecret: Uint8Array): Promise<Uint8Array> {
        const commandAPDUEncoder = this.getAPDUSimulator(sharedSecret, 1);
        const rbCommand = RDEDocument.readBinaryCommand(this.enrollmentParameters.Fid, this.enrollmentParameters.n);
        return await commandAPDUEncoder.writeCommand(rbCommand);
    }

    async deriveEncryptionKey(sharedSecret: Uint8Array): Promise<string> {
        const responseAPDUEncoder = this.getAPDUSimulator(sharedSecret, 2);
        const emulatedResponse = await responseAPDUEncoder.writeResponse(hexToBytes(this.enrollmentParameters.Fcont));
        return RDEDocument.getDecryptionKeyFromAPDUResponse(emulatedResponse);
    }

    private getAPDUSimulator(sharedSecret : Uint8Array, ssc : number) : AESAPDUEncoder {
        const ksEnc = RDEDocument.deriveKey(toHexString(sharedSecret), this.cipherAlg, this.keyLength, RDEDocument.ENC_MODE);
        const ksMac = RDEDocument.deriveKey(toHexString(sharedSecret), this.cipherAlg, this.keyLength, RDEDocument.MAC_MODE);
        return new AESAPDUEncoder(ksEnc, ksMac, ssc);
    }

    static generateKeyPair(curve: elliptic.ec): elliptic.ec.KeyPair {
        // const pcdKeyPair = curve.keyFromPrivate("487FF32745997CC30EA75E0DA8E5B2E586C23D9B3EDC9A1CE0529D3813B419338D9E9482AD0DF71C") // should result in key 362465D7EB40AF716CF003D5C94F39D3E3ACB4027277CD1067E28BC75D0FB289
        // return pcdKeyPair;
        return curve.genKeyPair()
    }
}

export default RDEKeyGenerator;