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
        const decryptionParams = new RDEDecryptionParameters(this.oid, pcdKeyPair.getPublic("hex"), toHexString(protectedCommand));
        return new RDEKey(encryptionKey, decryptionParams);
    }

    async deriveEncryptionKey(sharedSecret: Uint8Array): Promise<string> {
        const apduSimulator = this.getAPDUSimulator(sharedSecret);
        const emulatedResponse = await apduSimulator.write(hexToBytes(this.enrollmentParameters.Fcont));
        return RDEDocument.getDecryptionKeyFromAPDUResponse(emulatedResponse);
    }

    async generateProtectedCommand(sharedSecret: Uint8Array): Promise<Uint8Array> {
        const apduSimulator = this.getAPDUSimulator(sharedSecret);
        const rbCommand = RDEDocument.readBinaryCommand(this.enrollmentParameters.Fid, this.enrollmentParameters.n);
        return await apduSimulator.writeCommand(rbCommand);
    }

    private getAPDUSimulator(sharedSecret : Uint8Array) : AESAPDUEncoder {
        const ksEnc = RDEDocument.deriveKey(toHexString(sharedSecret), this.cipherAlg, this.keyLength, RDEDocument.ENC_MODE);
        const ksMac = RDEDocument.deriveKey(toHexString(sharedSecret), this.cipherAlg, this.keyLength, RDEDocument.MAC_MODE);
        return new AESAPDUEncoder(ksEnc, ksMac);
    }

    static generateKeyPair(curve: elliptic.ec): elliptic.ec.KeyPair {
        // const pcdPublicKey = pcdKeyPair.getPublic();
        // const pcdPrivateKey = pcdKeyPair.getPrivate();
        return curve.genKeyPair()
    }
}

export default RDEKeyGenerator;