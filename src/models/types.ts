export type Scalar = bigint;

export interface Point {
    x: Scalar;
    y: Scalar;

    addPoint(point: Point): Point;
    mulScalar(scalar: Scalar): Point;
    invert(): Point;
    pack(): Buffer;
    toString(): string;
    toArray(): Array<Scalar>;
    equals(obj: Point): boolean;
}

export type Scope = string[];

export type PublicParameters = {
    authorityKey: Point;
    elGamalBasePoint: Point;
    elGamalPPoint: Point;
    votingOptions: Array<Vote>;
}

export type Vote = 1n | 2n;