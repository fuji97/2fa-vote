import * as eccrypto from "eccrypto";
import * as crypto from "crypto";
import assert from "assert";

export type KeyPair = {
    privateKey: Buffer;
    publicKey: Buffer;
}

export type Sign = string;

export function generateKeypair(): KeyPair {
    const priv = eccrypto.generatePrivate();
    return {
        privateKey: priv,
        publicKey: eccrypto.getPublic(priv)
    }
}

export async function sign(msg: string, privKey: Buffer): Promise<Sign> {
    const hash = crypto.createHash("sha256").update(msg).digest();
    const sign = await eccrypto.sign(privKey, hash);

    return sign.toString('hex');
}

export async function verify(msg: string, pubKey: Buffer, sig: Sign): Promise<void> {
    const hash = crypto.createHash("sha256").update(msg).digest();

    await eccrypto.verify(pubKey, hash, Buffer.from(sig, 'hex'));
}