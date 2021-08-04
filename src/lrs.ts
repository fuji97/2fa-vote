// @ts-ignore
import lrs from "lrs";
import {Scope} from "./types";

export type LrsSign = string

export function sign(message: string, prvKey: string, scope: Scope) : LrsSign {
    return lrs.sign(scope, prvKey, message);
}

export function verify(message: string, sign: LrsSign, scope: Scope): boolean {
    return lrs.verify(scope, sign, message);
}

export function link(sign1: LrsSign, sign2: LrsSign): boolean {
    return lrs.link(sign1, sign2);
}