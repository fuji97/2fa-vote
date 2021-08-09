import {PublicParameters, Vote} from "./types";
import * as eddsa from "./eddsa";
import * as babyjubjub from "./babyjubjub";
import assert from "assert";
import {EncryptedVote} from "./Caster";
import * as lrs from "./lrs";
import { CesvInput,  CesvPublicInput, CeviPublicInput, cesv, cevi} from "./proof";
import {ElGamal} from "./elgamal";
import {Ballot, BallotConverter} from "./ballot";
import * as ecdsa from "./ecdsa";

export type CastedVote = {
    vote: Vote;
    sign: eddsa.Sign;
    pubKey: eddsa.PublicKey;
}

export class Voter {
    keypair: lrs.KeyPair;
    publicParameters: PublicParameters;
    scope: Array<string>;
    caster: Buffer; // TDO Change to more clean rappresentation
    keys: Array<eddsa.KeyPair>;

    constructor(keypair: lrs.KeyPair, scope: Array<string>, caster: Buffer, publicParameters: PublicParameters) {
        this.keypair = keypair;
        this.caster = caster;
        this.publicParameters = publicParameters;
        this.scope = scope;

        this.keys = new Array<eddsa.KeyPair>();
    }

    castVote(vote: Vote): CastedVote {
        const pair = eddsa.generateKeypair();
        let sig = eddsa.sign(vote, pair.privateKey);

        // Check signature
        assert(eddsa.verify(vote, pair.publicKey, sig), "Invalid EdDSA MiMC-7 signature");

        this.keys.push(pair);

        return {
            vote,
            sign: sig,
            pubKey: pair.publicKey
        }
    }

    async checkEncryptedBallot(ballot: EncryptedVote) {
        await cesv.verifyProof(ballot.cesv.proof, ballot.cesv.publicSignals);
        this.checkCesvInput(cesv.fromArray(ballot.cesv.publicSignals), ballot.vote);

        await cevi.verifyProof(ballot.cevi.proof, ballot.cevi.publicSignals);
        this.checkCeviInput(cevi.fromArray(ballot.cevi.publicSignals), ballot.vote);
    }

    checkCesvInput(input: CesvPublicInput, ballot: ElGamal): void {
        assert(babyjubjub.Point.fromArray(input.C).equals(ballot.C), "Invalid C");
        assert(babyjubjub.Point.fromArray(input.D).equals(ballot.D), "Invalid D");
        assert(babyjubjub.Point.fromArray(input.P).equals(this.publicParameters.elGamalPPoint), "Invalid P Point");
        assert(babyjubjub.Point.fromArray(input.B).equals(this.publicParameters.elGamalBasePoint), "Invalid Base Point");
        assert(babyjubjub.Point.fromArray(input.Y).equals(this.publicParameters.authorityKey), "Invalid Authority public key");

        assert(this.keys.some(x => babyjubjub.Point.fromArray(input.pub).equals(x.publicKey)), "Signing key not found");
    }

    checkCeviInput(input: CeviPublicInput, ballot: ElGamal): void {
        assert(babyjubjub.Point.fromArray(input.C).equals(ballot.C), "Invalid C");
        assert(babyjubjub.Point.fromArray(input.D).equals(ballot.D), "Invalid D");
        assert(babyjubjub.Point.fromArray(input.P).equals(this.publicParameters.elGamalPPoint), "Invalid P Point");
        assert(babyjubjub.Point.fromArray(input.B).equals(this.publicParameters.elGamalBasePoint), "Invalid Base Point");
        assert(babyjubjub.Point.fromArray(input.Y).equals(this.publicParameters.authorityKey), "Invalid Authority public key");
    }

    signBallot(ballot: Ballot): Ballot {
        const voteStr = BallotConverter.voteToHexString(ballot);
        ballot.voterSign = lrs.sign(voteStr, this.keypair, this.scope);

        assert(lrs.verify(voteStr, ballot.voterSign, this.scope), "Invalid Linkable Ring Signature");

        return ballot;
    }

    async verifyCasterSign(ballot: Ballot): Promise<void> {
        await ecdsa.verify(BallotConverter.voteToHexString(ballot), this.caster, <ecdsa.Sign>ballot.casterSign);
    }
}