import {AesCmac} from "aes-cmac";
import {CBC, ECB} from "aes-ts";

class AESAPDUEncoder {
    static DO87_CIPHER = "AES-CBC"
    static IV_CIPHER = "AES-ECB"
    static MAC_ALGO = "AESCMAC"
    static AES_KEY_SPEC_NAME = "AES"
    static BLOCK_SIZE = 16 //Plain text block size cos AES and AESCMAC
    static SW1 = 0x90
    static SW2 = 0x00
    static DATA_BLOCK_START_TAG = 0x87
    static DATA_BLOCK_LENGTH_END_TAG = 0x01
    static MAC_LENGTH = 0x08
    static MAC_BLOCK_START_TAG = 0x8e
    static RESPONSE_RESULT_BLOCK = [0x99, 0x02, this.SW1, this.SW2]
    static ssc1 = new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]) //0 when CA session started, first command is 1, first response is 2.
    static ssc2 = new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]) //0 when CA session started, first command is 1, first response is 2.

    private readonly ksEncData : Uint8Array
    private readonly ksMacData: Uint8Array

    private outputStream: Uint8Array;

    constructor(ksEnc : Uint8Array, ksMac : Uint8Array) {
        this.ksEncData = ksEnc
        this.ksMacData = ksMac;
    }


    encodeLe(le : number) : Uint8Array {
        if (0 <= le && le <= 256) {
            /* NOTE: Both 0x00 and 0x100 are mapped to 0x00. */
            return new Uint8Array([le]);
        } else {
            return new Uint8Array([(le & 0xFF00) >> 8, le & 0xFF]);
        }
    }
    async writeCommand(data: Uint8Array) {
        if (data.byteLength == 0) throw new Error("Empty data")
        const cla = data[0] & 0xff;
        const ins = data[1] & 0xff;
        const p1 = data[2] & 0xff;
        const p2 = data[3] & 0xff;
        const lc = data[4]; // ??
        const le = data[5]; // length

        const maskedHeader = new Uint8Array([(cla || 0x0C), ins, p1, p2]);
        const paddedMaskedHeader = AESAPDUEncoder.padBytes(maskedHeader, AESAPDUEncoder.BLOCK_SIZE); // TODO check getPadLength()

        let do8587 = new Uint8Array(0)
        let do97 = new Uint8Array(0)
        if (le > 0) {
            const encodedLe = this.encodeLe(le)
            do97 = new Uint8Array(encodedLe.byteLength + 2)
            do97.set(new Uint8Array([0x97]), 0)
            do97.set(new Uint8Array([0x01]), 1)  // TODO lenoflen consruction required here instead of 1 byte
            do97.set(encodedLe, 2)
        }

        let output = new Uint8Array(AESAPDUEncoder.ssc1.byteLength + paddedMaskedHeader.byteLength + do97.byteLength);
        output.set(AESAPDUEncoder.ssc1, 0);  // getEncodedSendSequenceCounter()
        output.set(paddedMaskedHeader, AESAPDUEncoder.ssc1.byteLength); // getEncodedSendSequenceCounter()
        // output.set(do8587, AESAPDUEncoder.ssc1.byteLength + paddedMaskedHeader.byteLength); // getEncodedSendSequenceCounter()
        output.set(do97, AESAPDUEncoder.ssc1.byteLength + paddedMaskedHeader.byteLength);
        const n = AESAPDUEncoder.padBytes(output, AESAPDUEncoder.BLOCK_SIZE); // TODO check getPadLength()

        const cc = await this.getMac(n)
        let ccLength = cc.length;
        if (ccLength != 8) {
            ccLength = 8;
        }

        const do8E = new Uint8Array(ccLength + 2);
        do8E.set([0x8E], 0);
        do8E.set([ccLength], 1);
        do8E.set(cc.slice(0, ccLength), 2);


        const resultData = new Uint8Array(do8587.byteLength + do97.byteLength + do8E.byteLength);
        resultData.set(do8587, 0);
        resultData.set(do97, do8587.byteLength);
        resultData.set(do8E, do8587.byteLength + do97.byteLength);

        const apduResult = new Uint8Array(resultData.byteLength + 6);
        apduResult.set(maskedHeader.slice(0, 4), 0);
        apduResult.set([resultData.byteLength], 4);
        apduResult.set(resultData, 5);
        apduResult.set([256], apduResult.byteLength - 1);
        return apduResult
    }

    async write(data: Uint8Array): Promise<Uint8Array> {
        if (data.byteLength == 0) throw new Error("Empty data")
        await this.writeDo87(data)
        this.writeDo99()
        await this.writeMac()
        const resultBytes = new Uint8Array([AESAPDUEncoder.SW1, AESAPDUEncoder.SW2])
        const result = new Uint8Array(this.outputStream.byteLength + resultBytes.byteLength)
        result.set(this.outputStream, 0)
        result.set(resultBytes, this.outputStream.byteLength)
        this.outputStream = result
        return this.outputStream
    }

    private async getMac(data: Uint8Array): Promise<Uint8Array> {
        const aesCmac = new AesCmac(this.ksMacData);
        return await aesCmac.calculate(data)
    }

    private async writeMac() {
        const paddedBytes = new Uint8Array(AESAPDUEncoder.padBytes(this.outputStream, AESAPDUEncoder.BLOCK_SIZE))
        const macData = new Uint8Array(paddedBytes.byteLength + AESAPDUEncoder.ssc2.byteLength)
        macData.set(AESAPDUEncoder.ssc2, 0)
        macData.set(paddedBytes, AESAPDUEncoder.ssc2.byteLength)
        const mac = await this.getMac(macData)
        const result = new Uint8Array(this.outputStream.byteLength + AESAPDUEncoder.MAC_LENGTH + 2)
        result.set(this.outputStream, 0)
        result.set(new Uint8Array([AESAPDUEncoder.MAC_BLOCK_START_TAG, AESAPDUEncoder.MAC_LENGTH]), this.outputStream.byteLength)
        result.set(mac.slice(0, AESAPDUEncoder.MAC_LENGTH), this.outputStream.byteLength + 2)
        this.outputStream = result
    }

    private writeDo99() {
        const data = new Uint8Array(AESAPDUEncoder.RESPONSE_RESULT_BLOCK.length + this.outputStream.byteLength)
        data.set(this.outputStream, 0)
        data.set(AESAPDUEncoder.RESPONSE_RESULT_BLOCK, this.outputStream.byteLength)
        this.outputStream = data
    }

    private async writeDo87(data: Uint8Array) {
        const encodedData = await this.getEncodedData(data)
        const sizeBlock = this.getEncodedDo87Size(encodedData.length)
        this.outputStream = new Uint8Array(encodedData.byteLength + sizeBlock.byteLength + 1)
        this.outputStream.set(new Uint8Array([AESAPDUEncoder.DATA_BLOCK_START_TAG]), 0)
        this.outputStream.set(sizeBlock, 1)
        this.outputStream.set(encodedData, sizeBlock.byteLength + 1)
    }

    private async getEncodedData(response: Uint8Array): Promise<Uint8Array> {
        if (response.byteLength == 0) return response
        const paddedResponse = this.getAlignedPlainText(response)

        const iv = this.getIv()
        // const algorithmSpec = {
        //     name: AESAPDUEncoder.DO87_CIPHER,
        //     iv: new Uint8Array(iv)
        // }
        // const ksEnc = await this.byteArrayToCryptoKey(this.ksEncData, AESAPDUEncoder.DO87_CIPHER, ["encrypt"])
        const cbc = new CBC(this.ksEncData, iv)
        return cbc.encrypt(paddedResponse)
        // const encrypted = await crypto.subtle.encrypt(algorithmSpec, ksEnc, paddedResponse) // cbc.encrypt(paddedResponse)
        // return new Uint8Array(encrypted)
    }

    private getAlignedPlainText(buffer: Uint8Array): Uint8Array {
        const paddedLength = AESAPDUEncoder.getPaddedLength(buffer.byteLength, AESAPDUEncoder.BLOCK_SIZE)
        if (paddedLength == buffer.byteLength)
            return buffer
        else
            return AESAPDUEncoder.padBytes(buffer, AESAPDUEncoder.BLOCK_SIZE)
    }

    private static getPaddedLength(bufferSize: number, blockSize: number): number {
        return Math.floor((bufferSize + blockSize) / blockSize) * blockSize;
    }

    private getEncodedDo87Size(paddedDo87Length: number): Uint8Array {
        const MIN_LONG_FORM_SIZE = 0x80
        const actualLength = paddedDo87Length + 1 //Cos of the 0x01 tag
        //Short form
        if (actualLength < MIN_LONG_FORM_SIZE) return new Uint8Array(
            [actualLength || AESAPDUEncoder.DATA_BLOCK_LENGTH_END_TAG]
        )

        //1 or 2 byte Long form
        let lenOfLen;
        if (actualLength > 0xff)
            lenOfLen = 2
        else
            lenOfLen = 1
        const result = new Uint8Array(lenOfLen + 2)
        result[0] = (MIN_LONG_FORM_SIZE + lenOfLen)

        let p = 1
        for (let i = lenOfLen - 1; i == 0; i--) {
            result[p++] = (actualLength >>> (i*8 && 0xff))
        }
        result[p++] = AESAPDUEncoder.DATA_BLOCK_LENGTH_END_TAG
        return result
    }

    private getIv(): Uint8Array {
        const aesEcb = new ECB(this.ksEncData);
        return aesEcb.encrypt(AESAPDUEncoder.ssc2)
    }

    public static padBytes(buffer: Uint8Array, blockSize: number): Uint8Array {
        return AESAPDUEncoder.pad(buffer, 0, buffer.byteLength, blockSize);
    }

    public static pad(bytes: Uint8Array, offset : number, bufferSize : number, blockSize : number) : Uint8Array {
        const paddedLength = AESAPDUEncoder.getPaddedLength(bufferSize, AESAPDUEncoder.BLOCK_SIZE);

        const result = new Uint8Array(paddedLength);
        result.set(bytes, 0);
        result.set(new Uint8Array(paddedLength - bufferSize).fill(0x00), bufferSize);
        result[bytes.length] = 0x80;
        return result;
    }
}

export default AESAPDUEncoder;