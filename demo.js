const enrollmentParamsField = document.getElementById('enrollmentParams');
const generateButton = document.getElementById('keygen');
const keyField = document.getElementById('key');
const decryptionParamsField = document.getElementById('decryptionParams');
const plaintextField = document.getElementById('plaintext');
const ciphertextField = document.getElementById('ciphertext');
const encryptButton = document.getElementById('encrypt');

const EC = elliptic.ec;
const curves = elliptic.curves;
const hash = elliptic.ec.hash;
const ASN1 = window.ASN1
const PEM = window.PEM


function hexToBase64(hexString) {
    return btoa(hexString.match(/\w{2}/g).map(function(a) {
        return String.fromCharCode(parseInt(a, 16));
    }).join(""));
}

function toHexString(byteArray) {
    var s = '';
    byteArray.forEach(function(byte) {
        s += ('0' + (byte & 0xFF).toString(16)).slice(-2);
    });
    return s;
}


async function generateKey() {
    const data = JSON.parse(enrollmentParamsField.value);

    const der = PEM.parseBlock(hexToBase64(data.piccPublicKey)).der;
    const json = ASN1.parse(der);

    const p = json.children[0].children[1].children[1].children[1].value;
    const a = json.children[0].children[1].children[2].children[0].value;
    const b = json.children[0].children[1].children[2].children[1].value;
    const n = json.children[0].children[1].children[4].value;
    const g = json.children[0].children[1].children[3].value;
    const x = g.slice(1, (g.length / 2) + 1);
    const y = g.slice(2 + ((g.length - 2) / 2));
    const curveSpec = new curves.PresetCurve({
        type: 'short',
        prime: null,
        p: toHexString(p),
        a: toHexString(a),
        b: toHexString(b),
        g: [
            toHexString(x),
            toHexString(y)
        ],
        n: toHexString(n),
        hash: hash.sha256,
        gRed: false,
    });
    const ec = new EC(curveSpec);

    const publicPoint = json.children[1].value;
    const publicPointX = publicPoint.slice(1, (g.length / 2) + 1);
    const publicPointY = publicPoint.slice(2 + ((g.length - 2) / 2));

    const caPub = {
        x: toHexString(publicPointX),
        y: toHexString(publicPointY)
    };
    const caPublicKey = ec.keyFromPublic(caPub, 'hex');
    console.log('Decoded CA public key: ', caPublicKey.getPublic('hex'));

    const ephemeralKeyPair = ec.genKeyPair();
    console.log('Generated PCD ephemeral public key: ', ephemeralKeyPair.getPublic('hex'));
    console.log('Generated PCD ephemeral private key: ', ephemeralKeyPair.getPrivate('hex'));

    const sharedSecret = ephemeralKeyPair.getPrivate().derive(caPublicKey.getPublic());
    console.log('Shared secret: ', sharedSecret.toString(16)); // should bee 66 of 67 and end sith 27 or something


    // var pcdPub = {
    //     x: "917941534483de2367c01ac6821264ea8e13a2595357dd42cc8439fb5b50086556334d3c0b0dcb89",
    //     y: "55650dfe69c46655a346c2a6fe29b80357dfe976c057e2f5e8813ec86d957593fa2e07bb6beac3a0"
    // }
    // var pcdPublicKey = ec.keyFromPublic(pcdPub, 'hex');
    // console.log('PCD public key: ', pcdPublicKey.getPublic('hex'));
    //
    // var pcdPriv = "6A942F08D1C1F11CCF68549CDFBDC9AFF8B8C95896B09C5DDF3BA22E35429163401434F31221C28D".toLowerCase()
    // var pcdPrivateKey = ec.keyFromPrivate(pcdPriv, 'hex');
    // console.log('PCD private key: ', pcdPrivateKey.getPrivate('hex'));
    //
    // var sharedSecret = pcdPrivateKey.derive(caPublicKey.getPublic());
    // console.log('Shared secret: ', sharedSecret.toString(16)); // should bee 66 of 67 and end sith 27 or something

}

function encrypt() {
    var key = JSON.parse(keyField.value);
}

generateButton.addEventListener('click', generateKey);
encryptButton.addEventListener('click', encrypt);


// const brainpoolP320r1 = new curves.PresetCurve({
//     type: 'short',
//     prime: null,
//     p: 'D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27'.toLowerCase(),
//     a: '3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4'.toLowerCase(),
//     b: '520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6'.toLowerCase(),
//     g: [
//         '43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611'.toLowerCase(),
//         '14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1'.toLowerCase(),
//     ],
//     hash: null,
//     gRed: false,
//     n: 'D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311'.toLowerCase(),
//     // q: 'D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311'.toLowerCase(),
//     // h: '1',
// });
//
// var ec = new EC(brainpoolP320r1);
//
//
// var caPub = {
//     x: "47c465b8d62c87a6320e5f8cee0d616fab1920da2fa48d8a0c38dbdcae2bc7a8d18be248918a3709",
//     y: "14cbc7d2cd80ea9f8e36e447b9dece44cc1f5a39fa81448fa43b9605541005a4618ae4c5ff5ad9fe"
// }
// var caPublicKey = ec.keyFromPublic(caPub, 'hex');
// console.log('CA public key: ', caPublicKey.getPublic('hex'));
//
// var pcdPub = {
//     x: "917941534483de2367c01ac6821264ea8e13a2595357dd42cc8439fb5b50086556334d3c0b0dcb89",
//     y: "55650dfe69c46655a346c2a6fe29b80357dfe976c057e2f5e8813ec86d957593fa2e07bb6beac3a0"
// }
// var pcdPublicKey = ec.keyFromPublic(pcdPub, 'hex');
// console.log('PCD public key: ', pcdPublicKey.getPublic('hex'));
//
// var pcdPriv = "6A942F08D1C1F11CCF68549CDFBDC9AFF8B8C95896B09C5DDF3BA22E35429163401434F31221C28D".toLowerCase()
// var pcdPrivateKey = ec.keyFromPrivate(pcdPriv, 'hex');
// console.log('PCD private key: ', pcdPrivateKey.getPrivate('hex'));
//
// var sharedSecret = pcdPrivateKey.derive(caPublicKey.getPublic());
// console.log('Shared secret: ', sharedSecret.toString(16));

