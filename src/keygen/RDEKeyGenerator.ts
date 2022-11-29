import RDEEnrollmentParameters from "../data/RDEEnrollmentParameters";
import DecryptionParameters from "../data/RDEDecryptionParameters";
import PassportUtils from "./PassportUtils";
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
        this.agreementAlg = PassportUtils.agreementAlgFromCAOID(this.oid)
        this.cipherAlg = PassportUtils.cipherAlgorithmFromCAOID(this.oid)
        this.keyLength = PassportUtils.keyLengthFromCAOID(this.oid)
        this.digestAlg = PassportUtils.digestAlgorithmForCipherAlgorithm(this.cipherAlg, this.keyLength)

        this.curve = PassportUtils.decodeCurve(enrollmentParameters.piccPublicKey)
        this.piccPublicKey = PassportUtils.decodeECPublicKey(this.curve, enrollmentParameters.piccPublicKey)
    }

    /**
     * Generates a key for the given RDE document.
     */
    async generateKey(): Promise<RDEKey> {
        const pcdKeyPair = RDEKeyGenerator.generateKeyPair(this.curve);
        const sharedSecret = new Uint8Array(pcdKeyPair.derive(this.piccPublicKey.getPublic()).toArray())

        const encryptionKey = await this.deriveEncryptionKey(sharedSecret);
        const protectedCommand = await this.generateProtectedCommand(sharedSecret);
        const pcdPublicKeyEncoded = PassportUtils.reencodeECPublicKey(this.enrollmentParameters.piccPublicKey, pcdKeyPair);
        const decryptionParams = new DecryptionParameters(this.enrollmentParameters.documentName, this.oid, utils.toHexString(pcdPublicKeyEncoded), utils.toHexString(protectedCommand));
        return new RDEKey(encryptionKey, decryptionParams);
    }

    /**
     * Generates a protected command for the given RDE document, required to retrieve the decryption key.
     * @param sharedSecret
     */
    async generateProtectedCommand(sharedSecret: Uint8Array): Promise<Uint8Array> {
        const commandAPDUEncoder = this.getAPDUSimulator(sharedSecret, 1);
        const rbCommand = PassportUtils.readBinaryCommand(this.enrollmentParameters.rdeDGId, this.enrollmentParameters.rdeRBLength);
        return await commandAPDUEncoder.writeCommand(rbCommand);
    }

    /**
     * Derives the encryption key from the given shared secret.
     * @param sharedSecret
     */
    async deriveEncryptionKey(sharedSecret: Uint8Array): Promise<Uint8Array> {
        const responseAPDUEncoder = this.getAPDUSimulator(sharedSecret, 2);
        const emulatedResponse = await responseAPDUEncoder.writeResponse(utils.hexToBytes(this.enrollmentParameters.rdeDGContent).slice(0, this.enrollmentParameters.rdeRBLength));
        return PassportUtils.getDecryptionKeyFromAPDUResponse(emulatedResponse);
    }

    private getAPDUSimulator(sharedSecret : Uint8Array, ssc : number) : AESAPDUEncoder {
        const ksEnc = PassportUtils.deriveKey(utils.toHexString(sharedSecret), this.cipherAlg, this.keyLength, PassportUtils.ENC_MODE);
        const ksMac = PassportUtils.deriveKey(utils.toHexString(sharedSecret), this.cipherAlg, this.keyLength, PassportUtils.MAC_MODE);
        return new AESAPDUEncoder(ksEnc, ksMac, ssc);
    }

    static generateKeyPair(curve: elliptic.ec): elliptic.ec.KeyPair {
        return curve.genKeyPair()
    }
}
