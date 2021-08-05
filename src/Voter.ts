import {KeyPair, PublicParameters, Vote, PublicKey, LrsKeyPair} from "./types";
import {EddsaSign, generateEddsaKeypair, sign, verify} from "./eddsa";
import {Point, scalarToPoint} from "./babyjubjub";
import assert from "assert";
// @ts-ignore
import {EncryptedVote} from "./Caster";
import * as lrs from "./lrs";
import {
    CesvInput,
    CesvInputConverter,
    CesvPublicInput, CeviInputConverter,
    CeviPublicInput,
    verifyCesvProof,
    verifyCeviProof
} from "./proof";
import {ElGamal} from "./elgamal";
import {Ballot, BallotConverter} from "./ballot";
import * as ecdsa from "./ecdsa";

export type CastedVote = {
    vote: Vote;
    sign: EddsaSign;
    pubKey: PublicKey;
}

export class Voter {
    keypair: LrsKeyPair;
    publicParameters: PublicParameters;
    scope: Array<string>;
    caster: Buffer; // TDO Change to more clean rappresentation
    keys: Array<KeyPair>;

    constructor(keypair: LrsKeyPair, scope: Array<string>, caster: Buffer, publicParameters: PublicParameters) {
        this.keypair = keypair;
        this.caster = caster;
        this.publicParameters = publicParameters;
        this.scope = scope;

        this.keys = new Array<KeyPair>();
    }

    castVote(vote: Vote): CastedVote {
        const pair = generateEddsaKeypair();
        let sig = sign(vote, pair.privateKey);

        // Check signature
        assert(verify(vote, pair.publicKey, sig), "Invalid EdDSA MiMC-7 signature");

        this.keys.push(pair);

        return {
            vote,
            sign: sig,
            pubKey: pair.publicKey
        }
    }

    async checkEncryptedBallot(ballot: EncryptedVote) {
        await verifyCesvProof(ballot.cesv.proof, ballot.cesv.publicSignals);
        this.checkCesvInput(CesvInputConverter.fromArray(ballot.cesv.publicSignals), ballot.vote);

        await verifyCeviProof(ballot.cevi.proof, ballot.cevi.publicSignals);
        this.checkCeviInput(CeviInputConverter.fromArray(ballot.cevi.publicSignals), ballot.vote);
    }

    checkCesvInput(input: CesvPublicInput, ballot: ElGamal): void {
        assert(Point.fromArray(input.C).equals(ballot.C), "Invalid C");
        assert(Point.fromArray(input.D).equals(ballot.D), "Invalid D");
        assert(Point.fromArray(input.P).equals(this.publicParameters.elGamalPPoint), "Invalid P Point");
        assert(Point.fromArray(input.B).equals(this.publicParameters.elGamalBasePoint), "Invalid Base Point");
        assert(Point.fromArray(input.Y).equals(this.publicParameters.authorityKey), "Invalid Authority public key");

        assert(this.keys.some(x => Point.fromArray(input.pub).equals(x.publicKey)), "Signing key not found");
    }

    checkCeviInput(input: CeviPublicInput, ballot: ElGamal): void {
        assert(Point.fromArray(input.C).equals(ballot.C), "Invalid C");
        assert(Point.fromArray(input.D).equals(ballot.D), "Invalid D");
        assert(Point.fromArray(input.P).equals(this.publicParameters.elGamalPPoint), "Invalid P Point");
        assert(Point.fromArray(input.B).equals(this.publicParameters.elGamalBasePoint), "Invalid Base Point");
        assert(Point.fromArray(input.Y).equals(this.publicParameters.authorityKey), "Invalid Authority public key");
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