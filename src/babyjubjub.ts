// @ts-ignore
import {babyJub as bjj} from "circomlib";
import * as types from "./types";
// @ts-ignore
import {Scalar} from "ffjavascript";
import assert from "assert";

export type PublicKey = Point;

export type KeyPair = {
    publicKey: PublicKey;
    privateKey: Scalar;
}

const bigInt = require("big-integer");

// TODO Check boundaries
const MIN_K = "1"
//const MAX_K = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
const MAX_K = "88242871839275222246405745257275088548364400416034343698204186575808495617"

export class Point implements types.Point {
    x: Scalar;
    y: Scalar;

    constructor(x: Scalar, y: Scalar) {
        this.x = x;
        this.y = y;
        assert(this.inCurve(), `The point ${this.toString()} is not on the curve`);
    }

    addPoint = (point: Point): Point => {
        let p = bjj.addPoint(this.toArray(), point.toArray());
        return Point.fromArray(p);
    };

    mulScalar = (scalar: Scalar): Point => {
        let p = bjj.mulPointEscalar(this.toArray(), scalar);
        return Point.fromArray(p);
    }

    invert = (): Point => {
        let a = bjj.F.e(0n - this.x);
        return new Point(a, this.y)
    }

    pack = (): Buffer => {
        return bjj.packPoint(this.toArray());
    }

    inCurve = (): boolean => {
        return bjj.inCurve(this.toArray());
    }

    inSubgroup = (): boolean => {
        return bjj.inSubgroup(this.toArray());
    }

    toString = (): string => {
        return `(${this.x.toString()},${this.y.toString()})`
    }

    toArray = (): Array<Scalar> => {
        return [this.x, this.y];
    }

    equals(obj: types.Point): boolean {
        return this.x == obj.x && this.y == obj.y;
    }

    static unpack = (buff: Buffer): Point => {
        let p = bjj.unpackPoint(buff);
        return Point.fromArray(p);
    }

    static fromArray = (point: Array<Scalar>): Point => {
        return pointFromArray(point);
    }
}

export const Generator = Point.fromArray(bjj.Generator);
export const Base8 = Point.fromArray(bjj.Base8);

export function randomScalar(min?: string, max?: string): Scalar {
    const rand = bigInt.randBetween(min ?? MIN_K, max ?? MAX_K);
    return BigInt(rand);
}

export function scalarToPoint(scalar: Scalar): Point {
    return Base8.mulScalar(scalar);
}

export function prv2pubSubgroup(scalar: Scalar): Point {
    return Base8.mulScalar(Scalar.shr(scalar, 3));
}
export function generateKeypairSubgroup(min?: string, max?: string): KeyPair {
    const priv = randomScalar(min, max);
    const pub = prv2pubSubgroup(priv);
    return {
        privateKey: priv,
        publicKey: pub
    }
}


export function generateKeypair(min?: string, max?: string): KeyPair {
    const priv = randomScalar(min, max);
    const pub = scalarToPoint(priv);
    return {
        privateKey: priv,
        publicKey: pub
    }
}

export function pointFromArray(arr: Array<Scalar>): Point {
    assert(arr.length == 2, "Invalid length");
    return new Point(arr[0], arr[1]);
}