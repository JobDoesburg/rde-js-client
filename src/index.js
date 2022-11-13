import RDEEnrollmentParameters from "./RDEEnrollmentParameters";
import RDEKeyGenerator from "./RDEKeyGenerator";
import RDEDecryptionHandshakeProtocol from "./DecryptionHandshakeProtocol";

const KEYSERVER = "https://keyserver.rde.jobdoesburg.dev"
const PROXYSERVER = "wss://proxyserver.rde.jobdoesburg.dev"

const emailField = document.getElementById('email');
const searchButton = document.getElementById('search');
const enrollmentParamsField = document.getElementById('enrollmentParams');
const generateButton = document.getElementById('keygen');
const keyField = document.getElementById('key');
const decryptionParamsField = document.getElementById('decryptionParams');
const retrievedKeyField = document.getElementById('retrievedKey');
const plaintextField = document.getElementById('plaintext');
const ciphertextField = document.getElementById('ciphertext');
const encryptButton = document.getElementById('encrypt');

const qrCodes = document.getElementById("qrcode");

const decryptHandshakeButton = document.getElementById('decryptHandshake');

let handshake;
let rdeKey;

async function generateKey() {
    const enrollmentData = RDEEnrollmentParameters.fromJson(enrollmentParamsField.value)
    const keyGenerator = new RDEKeyGenerator(enrollmentData)
    rdeKey = await keyGenerator.generateKey()
    keyField.innerText = rdeKey.encryptionKey
    decryptionParamsField.innerText = JSON.stringify(rdeKey.decryptionParameters)

}
async function encrypt() {
    console.log("Not implemented")
}

async function search() {
    const email = emailField.value
    const response = await fetch(KEYSERVER + "/api/search/?email=" + email);
    const data = await response.json();
    if (data == null)
        enrollmentParamsField.innerText = "No enrollment parameters found for this email address"
    else
        enrollmentParamsField.innerText = JSON.stringify(data[0]["enrollment_parameters"])
}

async function startHandshake(socket, url) {
    console.log("Starting handshake")
    handshake = new RDEDecryptionHandshakeProtocol(window.crypto, socket, rdeKey.decryptionParameters);
    const qrCode = new QRCode(document.getElementById("qrcode"), {
        text: url,
    });
    await handshake.performHandshake()
}

async function decryptHandshake() {
    const randomToken = crypto.getRandomValues(new Uint32Array(1))[0]
    console.log("Random token: " + randomToken)
    const url = PROXYSERVER + '/socket/' + randomToken
    const socket = await new WebSocket( url);
    socket.onopen = function (event) {
        startHandshake(socket, url)
    }
    socket.onmessage = function (event) {
        qrCodes.innerHTML = ""
    }
    socket.onclose = function (event) {
        console.log("Connection closed", event)
        retrievedKeyField.innerText = handshake.getRetrievedKey()
        qrCodes.innerHTML = ""
    }
    socket.onerror = function (event) {
        console.log("Connection error", event)
        qrCodes.innerHTML = ""
    }
}

searchButton.addEventListener('click', search);
generateButton.addEventListener('click', generateKey);
encryptButton.addEventListener('click', encrypt);
decryptHandshakeButton.addEventListener('click', decryptHandshake);

