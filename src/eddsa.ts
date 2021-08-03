import {Axis, KeyPair, Point} from "./types";
import {pointFromArray, prv2pubSubgroup, randomScalar, scalarToPoint} from "./babyjubjub";
// @ts-ignore
import {F1Field, Scalar} from "ffjavascript";
import {bigintToBuf} from "bigint-conversion";
const babyJub = require("circomlib").babyJub;
const mimc7 = require("circomlib").mimc7;
const eddsa = require("circomlib").eddsa;
//import {babyJub, mimc7} from "circomlib";

export type EddsaSign = {
    R8: Point;
    S: Axis;
}

// export function sign(msg: Axis, privKey: Axis): EddsaSign {
//     const A = prv2pubSubgroup(privKey).toArray();
//
//     const Fr = new F1Field(babyJub.subOrder);
//     let r = Fr.e(msg);
//     const R8 = babyJub.mulPointEscalar(babyJub.Base8, r);
//     const hm = mimc7.multiHash([R8[0], R8[1], A[0], A[1], msg]);
//     const S = Fr.add(r , Fr.mul(hm, privKey));
//     return {
//         R8: pointFromArray(R8),
//         S: S
//     };
// }

export function prv2pub(privKey: Axis): Point {
    return pointFromArray(eddsa.prv2pub(Buffer.from(privKey.toString(16), 'hex')));
}

export function generateEddsaKeypair(): KeyPair {
    const privKey = randomScalar();
    return {
        privateKey: privKey,
        publicKey: prv2pub(privKey)
    }
}

export function sign(msg: Axis, privKey: Axis): EddsaSign {
    const buff = Buffer.from(privKey.toString(16), 'hex');
    const res = eddsa.signMiMC(buff, msg);
    return {
        R8: pointFromArray(res.R8),
        S: res.S
    }
}

export function verify(msg: Axis, pubKey: Point, sign: EddsaSign): boolean {
    let A = pubKey.toArray();
    let sig = {
        S: sign.S,
        R8: sign.R8.toArray()
    };
    return eddsa.verifyMiMC(msg, sig, A);
}


// export function verify(msg: Axis, pubKey: Point, sign: EddsaSign): boolean {
//     let A = pubKey.toArray();
//     let sig = {
//         S: sign.S,
//         R8: sign.R8.toArray()
//     };
//
//     // Check parameters
//     if (typeof sig != "object") return false;
//     if (!Array.isArray(sig.R8)) return false;
//     if (sig.R8.length!= 2) return false;
//     if (!babyJub.inCurve(sig.R8)) return false;
//     if (!Array.isArray(A)) return false;
//     if (A.length!= 2) return false;
//     if (!babyJub.inCurve(A)) return false;
//     if (sig.S>= babyJub.subOrder) return false;
//
//     const hm = mimc7.multiHash([sig.R8[0], sig.R8[1], A[0], A[1], msg]);
//
//     const Pleft = babyJub.mulPointEscalar(babyJub.Base8, sig.S);
//     let Pright = babyJub.mulPointEscalar(A, Scalar.mul(hm, 8));
//     Pright = babyJub.addPoint(sig.R8, Pright);
//
//     if (!babyJub.F.eq(Pleft[0],Pright[0])) return false;
//     if (!babyJub.F.eq(Pleft[1],Pright[1])) return false;
//     return true;
// }