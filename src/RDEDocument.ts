import Hex from "@lapo/asn1js/hex";
import hash from "hash.js";
import ASN1, {Binary} from "@lapo/asn1js";
import elliptic, {curves} from "elliptic";

class RDEDocument {
    public static ID_CA_DH_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.3.1.1";
    public static ID_CA_ECDH_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.3.2.1";
    public static ID_CA_DH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.1.2";
    public static ID_CA_DH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.1.3";
    public static ID_CA_DH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.1.4";
    public static ID_CA_ECDH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.2.2";
    public static ID_CA_ECDH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.2.3";
    public static ID_CA_ECDH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.2.4";

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

    static getContentFromASNStream(asnData: any) : string {
        return asnData.stream.hexDump(asnData.posContent(), asnData.posEnd(), true).toLowerCase();
    }

    static decodeCurve(publicKeyData : Binary) : elliptic.ec {
        const json = ASN1.decode(Hex.decode(publicKeyData))
        const p = RDEDocument.getContentFromASNStream(json.sub[0].sub[1].sub[1].sub[1]);
        const a = RDEDocument.getContentFromASNStream(json.sub[0].sub[1].sub[2].sub[0]);
        const b = RDEDocument.getContentFromASNStream(json.sub[0].sub[1].sub[2].sub[1]);
        const n = RDEDocument.getContentFromASNStream(json.sub[0].sub[1].sub[4]);
        const g = RDEDocument.getContentFromASNStream(json.sub[0].sub[1].sub[3]);
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

    static decodePublicKey(curve : elliptic.ec, publicKeyData : Binary) : elliptic.ec.KeyPair {
        const json = ASN1.decode(Hex.decode(publicKeyData))
        const point = RDEDocument.getContentFromASNStream(json.sub[1]);
        const x = point.slice(4, 4 + ((point.length - 4) / 2));
        const y = point.slice(4 + ((point.length - 4) / 2));
        const pubPoint = {
            x: x,
            y: y
        };
        return curve.keyFromPublic(pubPoint, 'hex');
    }

    static deriveKey(sharedSecret : string, cipherAlgorithm : string, keyLength : number, mode : string) : Uint8Array {
        const digestAlgorithm = RDEDocument.digestAlgorithmForCipherAlgorithm(cipherAlgorithm, keyLength);
        const digest = digestAlgorithm()
        digest.update(sharedSecret, "hex");
        if (mode === RDEDocument.ENC_MODE) {
            digest.update("00000001", "hex");
        } else if (mode === RDEDocument.MAC_MODE) {
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

    static readBinaryCommand(sfi: number, le: number) {
        const sfiByte = 0x80 | (sfi & 0xFF);
        return new Uint8Array([0x00, 0xB0, sfiByte, 0x00, 0x00, le]);

    }

    static getDecryptionKeyFromAPDUResponse(apduResponse: Uint8Array) : string {
        return hash.sha256().update(apduResponse, 'hex').digest('hex');
    }
}

export default RDEDocument;