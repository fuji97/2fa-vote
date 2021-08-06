export type Axis = bigint;

export interface Point {
    x: Axis;
    y: Axis;

    addPoint(point: Point): Point;
    mulScalar(scalar: Axis): Point;
    invert(): Point;
    pack(): Buffer;
    toString(): string;
    toArray(): Array<Axis>;
    equals(obj: Point): boolean;
}

export type Scope = string[];

export type PublicKey = Point;

export type KeyPair = {
    publicKey: PublicKey;
    privateKey: Axis;
}

export type LrsKeyPair = {
    publicKey: string;
    privateKey: string;
}

export type PublicParameters = {
    authorityKey: Point;
    elGamalBasePoint: Point;
    elGamalPPoint: Point;
    votingOptions: Array<Vote>;
}

export type Vote = 1n | 2n;