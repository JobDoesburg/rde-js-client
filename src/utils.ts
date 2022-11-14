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
