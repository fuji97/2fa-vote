
// @ts-ignore
import {babyJub as bjj} from "circomlib";
import {Axis, Point as _Point} from "./types";
import assert from "assert";
import randBetween from "big-integer";

// TODO Check boundaries
const MIN_K = "1"
const MAX_K = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

export class Point implements _Point {
    x: Axis;
    y: Axis;

    constructor(x: Axis, y: Axis) {
        this.x = x;
        this.y = y;
        assert(this.inCurve(), `The point ${this.toString()} is not on the curve`);
    }

    addPoint = (point: Point): Point => {
        let p = bjj.addPoint(this.toArray(), point.toArray());
        return Point.fromArray(p);
    };

    mulScalar = (scalar: Axis): Point => {
        let p = bjj.mulPointEscalar(this.toArray(), scalar);
        return Point.fromArray(p);
    }

    invert = (): Point => {
        return new Point(0n - this.x, this.y)
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

    toArray = (): Array<Axis> => {
        return [this.x, this.y];
    }

    static unpack = (buff: Buffer): Point => {
        let p = bjj.unpackPoint(buff);
        return Point.fromArray(p);
    }

    static fromArray = (point: Array<Axis>): Point => {
        return new Point(point[0], point[1]);
    }
}

export const Generator = Point.fromArray(bjj.Generator);
export const Base8 = Point.fromArray(bjj.Base8);

export function randomScalar(min?: string, max?: string, rng?: () => number): Axis {

    // @ts-ignore
    return BigInt(randBetween(min ?? MIN_K, max ?? MAX_K, rng));
}
