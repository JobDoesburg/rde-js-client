import DecryptionParameters from "../data/RDEDecryptionParameters";

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

    constructor(crypto: Crypto, socket : WebSocket, decryptionParameters : DecryptionParameters) {
        this.socket = socket
        this.crypto = crypto;
        this.decryptionParameters = decryptionParameters
    }

    static async exportKey(crypto : Crypto, key : CryptoKey) : Promise<JsonWebKey> {
        return await crypto.subtle.exportKey("jwk", key)
    }

    static async importKey(crypto : Crypto, keyData: JsonWebKey) : Promise<CryptoKey> {
        return await crypto.subtle.importKey("jwk", keyData, RDEDecryptionHandshakeProtocol.keyAlgorithm, true, []);
    }

    private async generateBrowserKeyPair() {
        this.browserKey = await this.crypto.subtle.generateKey(RDEDecryptionHandshakeProtocol.keyAlgorithm, true, ["deriveKey"]);
    }

    async sendEncrypted(data : string) {
        const encryptedData = await this.crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: this.iv
            },
            this.sharedKey,
            new TextEncoder().encode(data)
        );
        console.log("Encrypted data", toHexString(new Uint8Array(encryptedData)));
        this.socket.send(encryptedData)
    }

    private async genIv() {
        this.iv = window.crypto.getRandomValues(new Uint8Array(16));
        console.log("iv", this.iv);
    }

    async sendBrowserKey() {
        const exportedBrowserKey = await RDEDecryptionHandshakeProtocol.exportKey(this.crypto, this.browserKey.publicKey);
        console.log("Browser key", this.browserKey);

        await this.genIv();
        const data = {
            "key": exportedBrowserKey,
            "iv": toHexString(this.iv)
        }
        console.log("Sending data", data);
        this.socket.send(JSON.stringify(data));
    }

    async sendDecryptionParameters() {
        await this.sendEncrypted(JSON.stringify(this.decryptionParameters))
    }

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

    async receiveAppKey(data: JsonWebKey) {
        this.appKey = await RDEDecryptionHandshakeProtocol.importKey(this.crypto, data)
        console.log("App key", this.appKey);
        await this.deriveSharedSecret()
    }

    async performHandshake() {
        await this.generateBrowserKeyPair();
        this.socket.addEventListener('message', this);
    }

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
            this.retrievedKey = await this.receiveRetrievedKey(hexToBytes(event.data));
            console.log("Retrieved key", this.retrievedKey);
            this.socket.close()
        }
    }

    getRetrievedKey() : string {
        return this.retrievedKey;
    }
}
