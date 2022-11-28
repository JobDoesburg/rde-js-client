import Hex from "@lapo/asn1js/hex";
import hash from "hash.js";
import ASN1, {Binary} from "@lapo/asn1js";
import elliptic, {curves} from "elliptic";
import utils from "../utils";

/**
 * Utility class with static methods for different kinds of RDE documents.
 */
export default class PassportUtils {
    public static ID_CA_DH_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.3.1.1";
    public static ID_CA_ECDH_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.3.2.1";
    public static ID_CA_DH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.1.2";
    public static ID_CA_DH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.1.3";
    public static ID_CA_DH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.1.4";
    public static ID_CA_ECDH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.2.2";
    public static ID_CA_ECDH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.2.3";
    public static ID_CA_ECDH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.2.4";

    public static EF_SOD_DG_HASH_SHA_224= "2.16.840.1.101.3.4.2.4"
    public static EF_SOD_DG_HASH_SHA_256= "2.16.840.1.101.3.4.2.1"
    public static EF_SOD_DG_HASH_SHA_384= "2.16.840.1.101.3.4.2.2"
    public static EF_SOD_DG_HASH_SHA_512= "2.16.840.1.101.3.4.2.3"

    public static ENC_MODE = "enc";
    public static MAC_MODE = "mac";

    static agreementAlgFromCAOID(oid: string): string {
        if (this.ID_CA_DH_3DES_CBC_CBC == oid
            || this.ID_CA_DH_AES_CBC_CMAC_128 == oid
            || this.ID_CA_DH_AES_CBC_CMAC_192 == oid
            || this.ID_CA_DH_AES_CBC_CMAC_256 == oid) {
            return "DH";
        } else if (this.ID_CA_ECDH_3DES_CBC_CBC == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_128 == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_192 == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_256 == oid) {
            return "ECDH";
        }
        throw new Error("Unknown CA OID");
    }

    static cipherAlgorithmFromCAOID(oid: string): string {
        if (this.ID_CA_DH_3DES_CBC_CBC == oid
            || this.ID_CA_ECDH_3DES_CBC_CBC == oid) {
            return "DESede";
        } else if (this.ID_CA_DH_AES_CBC_CMAC_128 == oid
            || this.ID_CA_DH_AES_CBC_CMAC_192 == oid
            || this.ID_CA_DH_AES_CBC_CMAC_256 == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_128 == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_192 == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_256 == oid) {
            return "AES";
        }
        throw new Error("Unknown CA OID");
    }

    static keyLengthFromCAOID(oid: string): number {
        if (this.ID_CA_DH_3DES_CBC_CBC == oid
            || this.ID_CA_ECDH_3DES_CBC_CBC == oid
            || this.ID_CA_DH_AES_CBC_CMAC_128 == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_128 == oid) {
            return 128;
        } else if (this.ID_CA_DH_AES_CBC_CMAC_192 == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_192 == oid) {
            return 192;
        } else if (this.ID_CA_DH_AES_CBC_CMAC_256 == oid
            || this.ID_CA_ECDH_AES_CBC_CMAC_256 == oid) {
            return 256;
        }
        throw new Error("Unknown CA OID");
    }

    static digestAlgorithmForCipherAlgorithm(cipherAlgorithm : String, keyLength : number) : any {
        if ("DESede" === cipherAlgorithm || "AES-128" === cipherAlgorithm) {
            return hash.sha1;
        }
        if ("AES" === cipherAlgorithm && keyLength === 128) {
            return hash.sha1;
        }
        if ("AES-256" === cipherAlgorithm || "AES-192" === cipherAlgorithm) {
            return hash.sha256;
        }
        if ("AES" === cipherAlgorithm && (keyLength === 192 || keyLength === 256)) {
            return hash.sha256;
        } else {
            throw new Error('Unsupported cipher algorithm');
        }
    }

    static digestAlgorithmNameFromHashOID(oid: string): any {
        if (this.EF_SOD_DG_HASH_SHA_256 == oid) {
            return "SHA-256";
        } else if (this.EF_SOD_DG_HASH_SHA_384 == oid) {
            return "SHA-384";
        } else if (this.EF_SOD_DG_HASH_SHA_512 == oid) {
            return "SHA-512";
        } else {
            throw new Error("Unsupported hash algorithm");
        }
    }

    static digestAlgorithmFromHashOID(oid: string): any {
        if (this.EF_SOD_DG_HASH_SHA_224 == oid) {
            return hash.sha224;
        } else if (this.EF_SOD_DG_HASH_SHA_256 == oid) {
            return hash.sha256;
        } else if (this.EF_SOD_DG_HASH_SHA_384 == oid) {
            return hash.sha384;
        } else if (this.EF_SOD_DG_HASH_SHA_512 == oid) {
            return hash.sha512;
        } else {
            throw new Error("Unsupported hash algorithm");
        }
    }

    static getContentFromASNStream(asnData: any) : string {
        return asnData.stream.hexDump(asnData.posContent(), asnData.posEnd(), true).toLowerCase();
    }

    /**
     * Encode a public key in the format used by the RDE protocol.
     * This is a very ugly hack to get the public key in the right format... but it works...
     * @param publicKeyData the existing encoded EC public key
     * @param newPublicKey the new public key to encode
     */
    static reencodeECPublicKey(publicKeyData : Binary, newPublicKey : elliptic.ec.KeyPair ) : Uint8Array {
        let data = utils.toHexString(new Uint8Array(Hex.decode(publicKeyData)));

        const json = ASN1.decode(Hex.decode(publicKeyData))
        const oldPoint = PassportUtils.getContentFromASNStream(json.sub[1]);
        let newPoint = newPublicKey.getPublic().encode('hex', false);
        newPoint = "00" + newPoint;
        data = data.replace(oldPoint, newPoint);

        return Hex.decode(data);
    }

    /**
     * Retrieve the elliptic curve used by the given public key.
     * @param publicKeyData the encoded public key
     */
    static decodeCurve(publicKeyData : Binary) : elliptic.ec {
        const json = ASN1.decode(Hex.decode(publicKeyData))
        const p = PassportUtils.getContentFromASNStream(json.sub[0].sub[1].sub[1].sub[1]);
        const a = PassportUtils.getContentFromASNStream(json.sub[0].sub[1].sub[2].sub[0]);
        const b = PassportUtils.getContentFromASNStream(json.sub[0].sub[1].sub[2].sub[1]);
        const n = PassportUtils.getContentFromASNStream(json.sub[0].sub[1].sub[4]);
        const g = PassportUtils.getContentFromASNStream(json.sub[0].sub[1].sub[3]);
        const x = g.slice(2, (g.length / 2) + 1);
        const y = g.slice(2 + ((g.length - 2) / 2));
        const curveSpec = new curves.PresetCurve({
            type: 'short',
            prime: null,
            p: p,
            a: a,
            b: b,
            g: [
                x,
                y
            ],
            n: n,
            gRed: false,
            hash: hash.sha256,
        });
        return new elliptic.ec(curveSpec);
    }

    /**
     * Decode the given public key.
     * @param curve the elliptic curve to use
     * @param publicKeyData the encoded public key
     */
    static decodeECPublicKey(curve : elliptic.ec, publicKeyData : Binary) : elliptic.ec.KeyPair {
        const json = ASN1.decode(Hex.decode(publicKeyData))
        const point = PassportUtils.getContentFromASNStream(json.sub[1]);
        const x = point.slice(4, 4 + ((point.length - 4) / 2));
        const y = point.slice(4 + ((point.length - 4) / 2));
        const pubPoint = {
            x: x,
            y: y
        };
        return curve.keyFromPublic(pubPoint, 'hex');
    }

    /**
     * Derive a cipher key from a shared secret.
     * @param sharedSecret the shared secret
     * @param cipherAlgorithm the cipher algorithm to use
     * @param keyLength the key length to use
     * @param mode the mode to use (either 'enc' or 'mac')
     */
    static deriveKey(sharedSecret : string, cipherAlgorithm : string, keyLength : number, mode : string) : Uint8Array {
        const digestAlgorithm = PassportUtils.digestAlgorithmForCipherAlgorithm(cipherAlgorithm, keyLength);
        const digest = digestAlgorithm()
        digest.update(sharedSecret, "hex");
        if (mode === PassportUtils.ENC_MODE) {
            digest.update("00000001", "hex");
        } else if (mode === PassportUtils.MAC_MODE) {
            digest.update("00000002", "hex");
        } else {
            throw new Error('Unsupported mode');
        }
        const hashResult = digest.digest();

        let keyBytes;
        if ("DESede" === cipherAlgorithm || "3DES" === cipherAlgorithm) {
            switch (keyLength) {
                case 112: /* Fall through. */
                case 128:
                    keyBytes = Uint8Array.from(hashResult.slice(0, 24));
                    keyBytes.copyWithin(16, 0, 8);
                    break;
                default:
                    throw new Error('KDF can only use DESede with 128-bit key length');
            }
            return keyBytes;
        } else if (cipherAlgorithm.startsWith("AES")) {
            switch (keyLength) {
                case 128:
                    keyBytes = Uint8Array.from(hashResult.slice(0, 16));
                    break;
                case 192:
                    keyBytes = Uint8Array.from(hashResult.slice(0, 24));
                    break;
                case 256:
                    keyBytes = Uint8Array.from(hashResult.slice(0, 32));
                    break;
                default:
                    throw new Error('KDF can only use AES with 128-bit, 192-bit key or 256-bit length');
            }
            return keyBytes;
        }
    }

    /**
     * The binary representation of the READ BINARY command APDU.
     * @see https://icao.int/publications/Documents/9303_p10_cons_en.pdf
     * @param sfi the SFI of the file to read
     * @param le the number of bytes to read
     */
    static readBinaryCommand(sfi: number, le: number) {
        const sfiByte = 0x80 | (sfi & 0xFF);
        return new Uint8Array([0x00, 0xB0, sfiByte, 0x00, 0x00, le]);

    }

    /**
     * Retrieve a key from the encrypted APDU response.
     * @param apduResponse
     */
    static getDecryptionKeyFromAPDUResponse(apduResponse: Uint8Array) : Uint8Array {
        return utils.hexToBytes(hash.sha256().update(apduResponse, 'hex').digest('hex'));
    }
}