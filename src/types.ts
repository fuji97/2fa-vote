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

export type PublicKey = Point;

export type KeyPair = {
    publicKey: PublicKey;
    privateKey: Axis;
}

export type PublicParameters = {
    authorityKey: Point;

}

export type Vote = 1n | 2n;