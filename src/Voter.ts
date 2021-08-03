import {KeyPair, PublicParameters, Vote, PublicKey} from "./types";
import {EddsaSign, generateKeypair, sign, verify} from "./eddsa";
import {scalarToPoint} from "./babyjubjub";
import assert from "assert";

export type CastedVote = {
    vote: Vote;
    sign: EddsaSign;
    pubKey: PublicKey;
}

export class Voter {
    keypair: KeyPair;
    publicParameters: PublicParameters;
    keys: Array<PublicKey>

    constructor(keypair: KeyPair, publicParameters: PublicParameters) {
        this.keypair = keypair;
        this.publicParameters = publicParameters;

        this.keys = new Array<PublicKey>();
    }

    castVote(vote: Vote): CastedVote {
        const pair = generateKeypair();
        let sig = sign(vote, pair.privateKey);

        // Check signature
        assert(verify(vote, pair.publicKey, sig), "Invalid EdDSA MiMC-7 signature");

        return {
            vote,
            sign: sig,
            pubKey: pair.publicKey
        }
    }
}