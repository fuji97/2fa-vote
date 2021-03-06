import * as ecdsa from "../cryptography/ecdsa";
import * as eccrypto from "eccrypto";
import * as crypto from "crypto";

const message = "Message to encrypt";
const keys = ecdsa.generateKeypair();

test("Test native ECDSA", async () => {
    const privKey = eccrypto.generatePrivate();
    const hash = crypto.createHash("sha256").update(message).digest();
    const sig = await eccrypto.sign(privKey, hash);
    const pubKey = eccrypto.getPublic(privKey);

    await expect(eccrypto.verify(pubKey, hash, sig)).resolves.toBeNull();
})

test("Test correct signature", async () => {
    const sig = await ecdsa.sign(message, keys.privateKey);

    await expect(ecdsa.verify(message, keys.publicKey, sig)).resolves.toBeTruthy();
})

test("Test invalid signature", async () => {
    const sig = await ecdsa.sign("Other message", keys.privateKey);

    await expect(ecdsa.verify(message, keys.publicKey, sig)).resolves.not.toBeTruthy();
})