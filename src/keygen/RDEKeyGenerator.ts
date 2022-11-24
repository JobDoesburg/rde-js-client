import RDEEnrollmentParameters from "../data/RDEEnrollmentParameters";
import DecryptionParameters from "../data/RDEDecryptionParameters";
import RDEDocument from "./RDEDocument";
import elliptic from "elliptic";
import AESAPDUEncoder from "./AESAPDUEncoder";
import RDEKey from "../data/RDEKey";
import utils from "../utils";

/**
 * Class for generating RDE keys.
 */
export default class RDEKeyGenerator {
    private readonly oid: string;
    private readonly agreementAlg: string;
    private readonly cipherAlg: string;
    private readonly keyLength: number;
    private readonly digestAlg: Hash;

    private readonly curve: elliptic.ec;
    private piccPublicKey: elliptic.ec.KeyPair;

    /**
     * Constructor for RDEKeyGenerator.
     * @param enrollmentParameters enrollment parameters of the RDE document to generate a key for
     */
    constructor(readonly enrollmentParameters : RDEEnrollmentParameters) {
        this.oid = enrollmentParameters.caOid
        this.agreementAlg = RDEDocument.agreementAlgFromCAOID(this.oid)
        this.cipherAlg = RDEDocument.cipherAlgorithmFromCAOID(this.oid)
        this.keyLength = RDEDocument.keyLengthFromCAOID(this.oid)
        this.digestAlg = RDEDocument.digestAlgorithmForCipherAlgorithm(this.cipherAlg, this.keyLength)

        this.curve = RDEDocument.decodeCurve(enrollmentParameters.piccPublicKey)
        this.piccPublicKey = RDEDocument.decodeECPublicKey(this.curve, enrollmentParameters.piccPublicKey)
    }

    /**
     * Generates a key for the given RDE document.
     */
    async generateKey(): Promise<RDEKey> {
        const pcdKeyPair = RDEKeyGenerator.generateKeyPair(this.curve);
        const sharedSecret = new Uint8Array(pcdKeyPair.derive(this.piccPublicKey.getPublic()).toArray())

        const encryptionKey = await this.deriveEncryptionKey(sharedSecret);
        const protectedCommand = await this.generateProtectedCommand(sharedSecret);
        const pcdPublicKeyEncoded = RDEDocument.reencodeECPublicKey(this.enrollmentParameters.piccPublicKey, pcdKeyPair);
        const decryptionParams = new DecryptionParameters(this.enrollmentParameters.documentName, this.oid, utils.toHexString(pcdPublicKeyEncoded), utils.toHexString(protectedCommand));
        return new RDEKey(encryptionKey, decryptionParams);
    }

    /**
     * Generates a protected command for the given RDE document, required to retrieve the decryption key.
     * @param sharedSecret
     */
    async generateProtectedCommand(sharedSecret: Uint8Array): Promise<Uint8Array> {
        const commandAPDUEncoder = this.getAPDUSimulator(sharedSecret, 1);
        const rbCommand = RDEDocument.readBinaryCommand(this.enrollmentParameters.rdeDGId, this.enrollmentParameters.rdeRBLength);
        return await commandAPDUEncoder.writeCommand(rbCommand);
    }

    /**
     * Derives the encryption key from the given shared secret.
     * @param sharedSecret
     */
    async deriveEncryptionKey(sharedSecret: Uint8Array): Promise<Uint8Array> {
        const responseAPDUEncoder = this.getAPDUSimulator(sharedSecret, 2);
        const emulatedResponse = await responseAPDUEncoder.writeResponse(utils.hexToBytes(this.enrollmentParameters.rdeDGContent));
        return RDEDocument.getDecryptionKeyFromAPDUResponse(emulatedResponse);
    }

    private getAPDUSimulator(sharedSecret : Uint8Array, ssc : number) : AESAPDUEncoder {
        const ksEnc = RDEDocument.deriveKey(utils.toHexString(sharedSecret), this.cipherAlg, this.keyLength, RDEDocument.ENC_MODE);
        const ksMac = RDEDocument.deriveKey(utils.toHexString(sharedSecret), this.cipherAlg, this.keyLength, RDEDocument.MAC_MODE);
        return new AESAPDUEncoder(ksEnc, ksMac, ssc);
    }

    static generateKeyPair(curve: elliptic.ec): elliptic.ec.KeyPair {
        return curve.genKeyPair()
    }
}
