import {Scalar, Point} from "./types";
import randBetween from "big-integer";
import {Base8, Generator} from "./babyjubjub";

export type ElGamal = {
    C: Point;
    D: Point;
}

export function encrypt(message: Point, pubKey: Point, k: Scalar): ElGamal {
    const c1 = Base8.mulScalar(k);  // TODO Choose Base8 or Generator
    const c2 = pubKey.mulScalar(k);
    const d = c2.addPoint(message);

    return {
        C: c1,
        D: d
    };
}

export function decrypt(encrypted: ElGamal, privKey: Scalar): Point {
    const c1 = encrypted.C.mulScalar(privKey).invert();

    return encrypted.D.addPoint(c1);
}