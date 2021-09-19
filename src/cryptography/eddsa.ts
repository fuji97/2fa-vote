import {Scalar, Point} from "../models/types";
import * as babyjubjub from "./babyjubjub";
// @ts-ignore
import {eddsa} from "../../node_modules/circomlib";

export type Sign = {
    R8: Point;
    S: Scalar;
}

export type PublicKey = Point;

export type KeyPair = {
    privateKey: Scalar;
    publicKey: Point;
}

export function prv2pub(privKey: Scalar): Point {
    return babyjubjub.pointFromArray(eddsa.prv2pub(Buffer.from(privKey.toString(16), 'hex')));
}

export function generateKeypair(): KeyPair {
    const privKey = babyjubjub.randomScalar();
    return {
        privateKey: privKey,
        publicKey: prv2pub(privKey)
    }
}

export function sign(msg: Scalar, privKey: Scalar): Sign {
    const buff = Buffer.from(privKey.toString(16), 'hex');
    const res = eddsa.signMiMC(buff, msg);
    return {
        R8: babyjubjub.pointFromArray(res.R8),
        S: res.S
    }
}

export function verify(msg: Scalar, pubKey: Point, sign: Sign): boolean {
    let A = pubKey.toArray();
    let sig = {
        S: sign.S,
        R8: sign.R8.toArray()
    };
    return eddsa.verifyMiMC(msg, sig, A);
}