import RDEEnrollmentParameters from "./RDEEnrollmentParameters";
import RDEKeyGenerator from "./RDEKeyGenerator";

const enrollmentParamsField = document.getElementById('enrollmentParams');
const generateButton = document.getElementById('keygen');
const keyField = document.getElementById('key');
const decryptionParamsField = document.getElementById('decryptionParams');
const plaintextField = document.getElementById('plaintext');
const ciphertextField = document.getElementById('ciphertext');
const encryptButton = document.getElementById('encrypt');


async function generateKey() {
    const enrollmentData = RDEEnrollmentParameters.fromJson(enrollmentParamsField.value)
    const keyGenerator = new RDEKeyGenerator(enrollmentData)
    const key = await keyGenerator.generateKey()
    keyField.innerText = key.encryptionKey
    decryptionParamsField.innerText = JSON.stringify(key.decryptionParameters)

}
async function encrypt() {
    console.log("Not implemented")
}

generateButton.addEventListener('click', generateKey);
encryptButton.addEventListener('click', encrypt);
