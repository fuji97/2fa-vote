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
}

export type KeyPair = {
    publicKey: Point;
    privateKey: Axis;
}

export type PublicParameters = {
    authorityKey: Point;

}