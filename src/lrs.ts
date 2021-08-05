// @ts-ignore
import lrs from "lrs";
import {LrsKeyPair, Scope} from "./types";

export type LrsSign = string

export function sign(message: string, keypair: LrsKeyPair, scope: Scope) : LrsSign {
    // TODO Hash message?
    return lrs.sign(scope, keypair, message);
}

export function verify(message: string, sign: LrsSign, scope: Scope): boolean {
    // TODO Hash message?
    return lrs.verify(scope, sign, message);
}

export function link(sign1: LrsSign, sign2: LrsSign): boolean {
    return lrs.link(sign1, sign2);
}

export function generateLrsKeypair(): LrsKeyPair {
    return lrs.gen();
}