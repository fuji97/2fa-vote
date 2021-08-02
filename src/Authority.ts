import {KeyPair, PublicParameters, Axis} from "./types";
import {Point} from "./types";
import {Base8} from "./babyjubjub";

type PublicKey = Point;
type Scope = Array<PublicKey>;

class Authority {
    pp: PublicParameters;
    keypair: KeyPair;
    verifiers: Array<PublicKey>;
    voters: Array<PublicKey>;
    casters: Map<PublicKey, Scope>;

    constructor(privKey: Axis) {
        this.keypair = {
            privateKey: privKey,
            publicKey: Base8.mulScalar(privKey)
        }
        this.pp = {
            authorityKey: this.keypair.publicKey
        };

        this.verifiers = new Array<Point>();
        this.voters = new Array<Point>();
        this.casters = new Map<PublicKey, Scope>();
    }
}