import {KeyPair, PublicParameters, Axis} from "./types";
import {Point} from "./types";
import {Base8} from "./babyjubjub";
import {decrypt, ElGamal} from "./elgamal";

type PublicKey = Point;
type Scope = Array<PublicKey>;

export class Authority {
    pp: PublicParameters;
    keypair: KeyPair;
    verifiers: Array<PublicKey>;
    voters: Array<PublicKey>;
    casters: Map<PublicKey, Scope>;

    constructor(keypair: KeyPair) {
        this.keypair = keypair;
        this.pp = {
            authorityKey: this.keypair.publicKey
        };

        this.verifiers = new Array<Point>();
        this.voters = new Array<Point>();
        this.casters = new Map<PublicKey, Scope>();
    }

    decrypt(enc: ElGamal): Point {
        return decrypt(enc, this.keypair.privateKey);
    }
}