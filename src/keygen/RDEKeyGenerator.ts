import RDEEnrollmentParameters from "../data/RDEEnrollmentParameters";
import DecryptionParameters from "../data/RDEDecryptionParameters";
import RDEDocument from "./RDEDocument";
import elliptic from "elliptic";
import AESAPDUEncoder from "./AESAPDUEncoder";
import RDEKey from "../data/RDEKey";


export default class RDEKeyGenerator {
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
        this.piccPublicKey = RDEDocument.decodeECPublicKey(this.curve, enrollmentParameters.piccPublicKey)
    }

    async generateKey(): Promise<RDEKey> {
        const pcdKeyPair = RDEKeyGenerator.generateKeyPair(this.curve);
        const sharedSecret = new Uint8Array(pcdKeyPair.derive(this.piccPublicKey.getPublic()).toArray())

        const encryptionKey = await this.deriveEncryptionKey(sharedSecret);
        const protectedCommand = await this.generateProtectedCommand(sharedSecret);
        const pcdPublicKeyEncoded = RDEDocument.reEncodeECPublicKey(this.enrollmentParameters.piccPublicKey, pcdKeyPair);
        const decryptionParams = new DecryptionParameters(this.oid, toHexString(pcdPublicKeyEncoded), toHexString(protectedCommand));
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
        return curve.genKeyPair()
    }
}
