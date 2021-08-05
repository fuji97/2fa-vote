import {KeyPair, PublicParameters, Axis, Scope} from "./types";
import {Point} from "./types";
import {Base8} from "./babyjubjub";
import {decrypt, ElGamal} from "./elgamal";
import {CasterData} from "./Caster";

type PublicKey = Point;

export class Authority {
    pp: PublicParameters;
    keypair: KeyPair;
    voters: Array<PublicKey>;
    casters: Map<number, CasterData>;

    constructor(keypair: KeyPair) {
        this.keypair = keypair;
        this.pp = {
            authorityKey: this.keypair.publicKey,
            elGamalBasePoint: Base8,
            elGamalPPoint: Base8
        };

        this.voters = new Array<Point>();
        this.casters = new Map<number, CasterData>();
    }

    decrypt(enc: ElGamal): Point {
        return decrypt(enc, this.keypair.privateKey);
    }
}