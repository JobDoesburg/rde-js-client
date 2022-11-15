import {AesCmac} from "aes-cmac";
import {CBC, ECB} from "aes-ts";

/**
 * This class is used to emulate how an RDE document would encode and decode APDU's, using AES-CBC and AES-CMAC,
 * following the ICAO 9303-11 standard.
 *
 * This class does NOT implement the full standard, but only the parts required for the RDE protocol. Not all
 * APDU's are supported, and not all APDU's are implemented correctly.
 *
 * @see https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
 */
export default class AESAPDUEncoder {
    static BLOCK_SIZE = 16
    static SW1 = 0x90
    static SW2 = 0x00
    static DATA_BLOCK_START_TAG = 0x87
    static DATA_BLOCK_LENGTH_END_TAG = 0x01
    static MAC_LENGTH = 0x08
    static MAC_BLOCK_START_TAG = 0x8e
    static RESPONSE_RESULT_BLOCK = [0x99, 0x02, this.SW1, this.SW2]
    static SSC_LENGTH = 16

    private readonly ksEncData : Uint8Array
    private readonly ksMacData: Uint8Array
    private ssc : Uint8Array = new Uint8Array(AESAPDUEncoder.SSC_LENGTH) // Session sequence number
    // 0 when CA session started, first command is 1, first response is 2

    constructor(ksEnc : Uint8Array, ksMac : Uint8Array, ssc : number = 1) {
        this.ksEncData = ksEnc
        this.ksMacData = ksMac;
        this.ssc[AESAPDUEncoder.SSC_LENGTH - 1] = ssc;
    }

    /**
     * Encode a command APDU.
     * @param commandData the unencrypted command apdu data to encode
     */
    async writeCommand(commandData: Uint8Array) {
        if (commandData.byteLength == 0) throw new Error("Empty data")
        const cla = commandData[0] & 0xff;
        const ins = commandData[1] & 0xff;
        const p1 = commandData[2] & 0xff;
        const p2 = commandData[3] & 0xff;
        const le = commandData[5]; // length

        const do8587 = this.do8587()
        const do97 = this.do97(le)
        const commandAPDU = this.constructCommandAPDU(cla, ins, p1, p2, do8587, do97)
        const do8E = await this.do8E(commandAPDU);

        const resultData = new Uint8Array(do8587.byteLength + do97.byteLength + do8E.byteLength);
        resultData.set(do8587, 0);
        resultData.set(do97, do8587.byteLength);
        resultData.set(do8E, do8587.byteLength + do97.byteLength);

        const apduResult = new Uint8Array(resultData.byteLength + 6);
        apduResult.set([(cla || 0x0C), ins, p1, p2], 0);
        apduResult.set([resultData.byteLength], 4);
        apduResult.set(resultData, 5);
        apduResult.set([256], apduResult.byteLength - 1);
        return apduResult
    }

    private do8587() {
        return new Uint8Array(0) // Not implemented because not used for RDE
    }

    private do97(le: number): Uint8Array {
        if (le <= 0) {
            return new Uint8Array(0);
        }
        const encodedLe = AESAPDUEncoder.encodeLe(le)
        const do97 = new Uint8Array(encodedLe.byteLength + 2)
        do97.set(new Uint8Array([0x97]), 0)
        do97.set(new Uint8Array([0x01]), 1)  // TODO lenoflen consruction required here instead of 1 byte
        do97.set(encodedLe, 2)
        return do97
    }

    /**
     * Create a command APDU from the given data.
     * @param cla application class byte
     * @param ins instruction byte
     * @param p1 parameter 1 byte
     * @param p2 parameter 2 byte
     * @param do8587 data object 8587
     * @param do97 data object 97
     * @private
     */
    private constructCommandAPDU(cla: number, ins: number, p1: number, p2: number, do8587: Uint8Array, do97: Uint8Array) : Uint8Array {
        const maskedHeader = new Uint8Array([(cla || 0x0C), ins, p1, p2]);
        const paddedMaskedHeader = AESAPDUEncoder.pad(maskedHeader);

        let output = new Uint8Array(AESAPDUEncoder.SSC_LENGTH + paddedMaskedHeader.byteLength + do8587.byteLength + do97.byteLength);
        output.set(this.ssc, 0);
        output.set(paddedMaskedHeader, AESAPDUEncoder.SSC_LENGTH);
        output.set(do8587, AESAPDUEncoder.SSC_LENGTH + paddedMaskedHeader.byteLength);
        output.set(do97, AESAPDUEncoder.SSC_LENGTH + paddedMaskedHeader.byteLength + do8587.byteLength);
        return AESAPDUEncoder.pad(output);
    }

    private async do8E(data: Uint8Array) : Promise<Uint8Array> {
        const cc = await this.getMac(data)
        let ccLength = cc.length;
        if (ccLength != 8) {
            ccLength = 8;
        }

        const do8E = new Uint8Array(ccLength + 2);
        do8E.set([0x8E], 0);
        do8E.set([ccLength], 1);
        do8E.set(cc.slice(0, ccLength), 2);
        return do8E
    }

    /**
     * Encode a response APDU.
     * @param responseData the unencrypted response apdu data to encode
     */
    async writeResponse(responseData: Uint8Array): Promise<Uint8Array> {
        if (responseData.byteLength == 0) throw new Error("Empty data")

        let response;

        response = await this.do87(responseData)
        response = this.do99(response)
        response = await this.doMac(response)

        const result = new Uint8Array(response.byteLength + 2)
        result.set(response, 0)
        result.set([AESAPDUEncoder.SW1, AESAPDUEncoder.SW2], response.byteLength)
        return result
    }

    /**
     * Get the AES-CMAC of the given data.
     * @param data the data to get the AES-CMAC of
     * @private
     */
    private async getMac(data: Uint8Array): Promise<Uint8Array> {
        const aesCmac = new AesCmac(this.ksMacData);
        return await aesCmac.calculate(data)
    }

    /**
     * Get the IV for the AES-CBC cipher (consisting of the AES-ECB encrypted SSC).
     * @private
     */
    private getIv(): Uint8Array {
        const aesEcb = new ECB(this.ksEncData);
        return aesEcb.encrypt(this.ssc)
    }

    /**
     * MAC the given data.
     * @param data the data to MAC
     * @private
     */
    private async doMac(data : Uint8Array) {
        const paddedBytes = new Uint8Array(AESAPDUEncoder.pad(data))
        const macData = new Uint8Array(paddedBytes.byteLength + AESAPDUEncoder.SSC_LENGTH)
        macData.set(this.ssc, 0)
        macData.set(paddedBytes, AESAPDUEncoder.SSC_LENGTH)
        const mac = await this.getMac(macData)
        const result = new Uint8Array(data.byteLength + AESAPDUEncoder.MAC_LENGTH + 2)
        result.set(data, 0)
        result.set(new Uint8Array([AESAPDUEncoder.MAC_BLOCK_START_TAG, AESAPDUEncoder.MAC_LENGTH]), data.byteLength)
        result.set(mac.slice(0, AESAPDUEncoder.MAC_LENGTH), data.byteLength + 2)
        return result
    }


    private do99(data : Uint8Array) {
        const result = new Uint8Array(AESAPDUEncoder.RESPONSE_RESULT_BLOCK.length + data.byteLength)
        result.set(data, 0)
        result.set(AESAPDUEncoder.RESPONSE_RESULT_BLOCK, data.byteLength)
        return result
    }


    private async do87(data: Uint8Array) {
        const encodedData = await this.getEncodedData(data)
        const sizeBlock = AESAPDUEncoder.getEncodedDo87Size(encodedData.length)
        const result = new Uint8Array(encodedData.byteLength + sizeBlock.byteLength + 1)
        result.set(new Uint8Array([AESAPDUEncoder.DATA_BLOCK_START_TAG]), 0)
        result.set(sizeBlock, 1)
        result.set(encodedData, sizeBlock.byteLength + 1)
        return result
    }

    private async getEncodedData(response: Uint8Array): Promise<Uint8Array> {
        if (response.byteLength == 0) return response
        const paddedResponse = this.getAlignedPlainText(response)

        const iv = this.getIv()
        const cbc = new CBC(this.ksEncData, iv)
        return cbc.encrypt(paddedResponse)
    }

    private getAlignedPlainText(buffer: Uint8Array): Uint8Array {
        const paddedLength = AESAPDUEncoder.getPaddedLength(buffer.byteLength)
        if (paddedLength == buffer.byteLength)
            return buffer
        else
            return AESAPDUEncoder.pad(buffer)
    }


    private static getEncodedDo87Size(paddedDo87Length: number): Uint8Array {
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

    private static encodeLe(le : number) : Uint8Array {
        if (0 <= le && le <= 256) {
            /* NOTE: Both 0x00 and 0x100 are mapped to 0x00. */
            return new Uint8Array([le]);
        } else {
            return new Uint8Array([(le & 0xFF00) >> 8, le & 0xFF]);
        }
    }

    private static getPaddedLength(bufferSize: number, blockSize: number = AESAPDUEncoder.BLOCK_SIZE): number {
        return Math.floor((bufferSize + blockSize) / blockSize) * blockSize;
    }

    private static pad(buffer: Uint8Array, blockSize: number = AESAPDUEncoder.BLOCK_SIZE): Uint8Array {
        return AESAPDUEncoder.padBytes(buffer, buffer.byteLength, blockSize);
    }

    private static padBytes(bytes: Uint8Array, bufferSize : number, blockSize : number) : Uint8Array {
        const paddedLength = AESAPDUEncoder.getPaddedLength(bufferSize, blockSize);

        const result = new Uint8Array(paddedLength);
        result.set(bytes.slice(0, bufferSize), 0);
        result.set(new Uint8Array(paddedLength - bufferSize).fill(0x00), bufferSize);
        result[bytes.length] = 0x80;
        return result;
    }
}
