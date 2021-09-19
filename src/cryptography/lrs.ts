// @ts-ignore
import lrs from "lrs";
import {Scope} from "../models/types";
import crypto from "crypto";

export type KeyPair = {
    publicKey: string;
    privateKey: string;
}

export type Sign = string

export function sign(message: string, keypair: KeyPair, scope: Scope) : Sign {
    const hash = crypto.createHash("sha256").update(message).digest();
    return lrs.sign(scope, keypair, hash);
}

export function verify(message: string, sign: Sign, scope: Scope): boolean {
    const hash = crypto.createHash("sha256").update(message).digest();
    return lrs.verify(scope, sign, hash);
}

export function link(sign1: Sign, sign2: Sign): boolean {
    return lrs.link(sign1, sign2);
}

export function generateKeypair(): KeyPair {
    return lrs.gen();
}