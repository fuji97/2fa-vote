import {Axis, Point} from "./types";
import randBetween from "big-integer";
import {Generator} from "./babyjubjub";

export type ElGamal = {
    C: Point;
    D: Point;
}

export function encrypt(message: Point, pubKey: Point, k: Axis): ElGamal {
    const c1 = Generator.mulScalar(k);
    const c2 = pubKey.mulScalar(k);
    const d = c2.addPoint(message);

    return {
        C: c1,
        D: d
    };
}

export function decrypt(encrypted: ElGamal, privKey: Axis): Point {
    const c1 = encrypted.C.mulScalar(privKey).invert();

    return encrypted.D.addPoint(c1);
}