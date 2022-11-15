import DecryptionParameters from "../data/RDEDecryptionParameters";
import utils from "../utils";

/**
 * Class for connecting with the RDE Android client app and retrieving the decryption key.
 */
export default class RDEDecryptionHandshakeProtocol {
    public static keyAlgorithm = {
        name: "ECDH",
        namedCurve: "P-384"
    }

    private readonly socket: WebSocket;
    private readonly crypto: Crypto;
    private readonly decryptionParameters: DecryptionParameters;

    private browserKey: CryptoKeyPair;
    private appKey: CryptoKey;
    private sharedKey: CryptoKey;
    private iv: Uint8Array;

    private retrievedKey: string;

    /**
     * Creates a new RDEDecryptionHandshakeProtocol instance.
     * @param crypto The crypto object to use for key generation and encryption.
     * @param socket The WebSocket to use for communication with the RDE Android client app.
     * @param decryptionParameters The decryption parameters to send to the RDE Android client app.
     */
    constructor(crypto: Crypto, socket : WebSocket, decryptionParameters : DecryptionParameters) {
        this.socket = socket
        this.crypto = crypto;
        this.decryptionParameters = decryptionParameters
    }

    private static async exportKey(crypto : Crypto, key : CryptoKey) : Promise<JsonWebKey> {
        return await crypto.subtle.exportKey("jwk", key)
    }

    private static async importKey(crypto : Crypto, keyData: JsonWebKey) : Promise<CryptoKey> {
        return await crypto.subtle.importKey("jwk", keyData, RDEDecryptionHandshakeProtocol.keyAlgorithm, true, []);
    }

    /**
     * Generates a new browser key pair, for use in the ECDH key exchange for communication with the RDE Android client app.
     * @private
     */
    private async generateBrowserKeyPair() {
        this.browserKey = await this.crypto.subtle.generateKey(RDEDecryptionHandshakeProtocol.keyAlgorithm, true, ["deriveKey"]);
    }

    /**
     * Sends the given data to the RDE Android client app, encrypted with the shared key.
     * @param data
     */
    async sendEncrypted(data : string) {
        const encryptedData = await this.crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: this.iv
            },
            this.sharedKey,
            new TextEncoder().encode(data)
        );
        console.log("Encrypted data", utils.toHexString(new Uint8Array(encryptedData)));
        this.socket.send(encryptedData)
    }

    /**
     * Generates a new IV for use in the AES-CBC encryption.
     * @private
     */
    private async genIv() {
        this.iv = window.crypto.getRandomValues(new Uint8Array(16));
        console.log("iv", this.iv);
    }

    /**
     * Sends the browser key to the RDE Android client app for use in the ECDH key exchange.
     */
    async sendBrowserKey() {
        const exportedBrowserKey = await RDEDecryptionHandshakeProtocol.exportKey(this.crypto, this.browserKey.publicKey);
        console.log("Browser key", this.browserKey);

        await this.genIv();
        const data = {
            "key": exportedBrowserKey,
            "iv": utils.toHexString(this.iv)
        }
        console.log("Sending data", data);
        this.socket.send(JSON.stringify(data));
    }

    /**
     * Sends the decryption parameters to the RDE Android client app over the socket.
     */
    async sendDecryptionParameters() {
        await this.sendEncrypted(JSON.stringify(this.decryptionParameters))
    }

    /**
     * Derives the shared secret from the browser key and the app key (this is the ECDH key exchange).
     * @private
     */
    private async deriveSharedSecret() {
        this.sharedKey = await this.crypto.subtle.deriveKey(
            {
                name: "ECDH",
                public: this.appKey
            },
            this.browserKey.privateKey,
            {
                name: "AES-CBC",
                length: 256
            },
            false,
            ["encrypt", "decrypt"]
        );
        console.log("Shared key", this.sharedKey);
    }

    /**
     * Receives the app public key from the RDE Android client app.
     * @param data
     */
    async receiveAppKey(data: JsonWebKey) {
        this.appKey = await RDEDecryptionHandshakeProtocol.importKey(this.crypto, data)
        console.log("App key", this.appKey);
        await this.deriveSharedSecret()
    }

    /**
     * Starts the handshake with the RDE Android client app.
     */
    async performHandshake() {
        await this.generateBrowserKeyPair();
        this.socket.addEventListener('message', this);
    }

    /**
     * Receives the retrieved key from the RDE Android client app.
     * @param data
     */
    async receiveRetrievedKey(data: ArrayBuffer) : Promise<string> {
        const decryptedKey = await this.crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: this.iv
            },
            this.sharedKey,
            data
        );
        console.log("Decrypted key", decryptedKey);
        const decryptedKeyString = new TextDecoder().decode(decryptedKey);
        console.log("Decrypted key string", decryptedKeyString);
        return decryptedKeyString;
    }

    /**
     * Handles messages received from the RDE Android client app.
     * @param event
     */
    async handleEvent(event: MessageEvent) {
        console.log("Received event: ", event);

        if (this.appKey == null) {
            const jsonData = JSON.parse(event.data);
            console.log("Received data: ", jsonData);
            await this.receiveAppKey(jsonData)
            await this.sendBrowserKey()
            console.log("Handshake complete");
            await this.sendDecryptionParameters()
        } else {
            this.retrievedKey = await this.receiveRetrievedKey(utils.hexToBytes(event.data));
            console.log("Retrieved key", this.retrievedKey);
            this.socket.close()
        }
    }

    /**
     * Returns the retrieved key from the RDE Android client app.
     */
    getRetrievedKey() : string {
        return this.retrievedKey;
    }
}
