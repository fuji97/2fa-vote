import {PublicParameters, Vote} from "../models/types";
import * as eddsa from "../cryptography/eddsa";
import * as babyjubjub from "../cryptography/babyjubjub";
import assert from "assert";
import {EncryptedVote} from "./Caster";
import * as lrs from "../cryptography/lrs";
import { CesvInput,  CesvPublicInput, CeviPublicInput, cesv, cevi} from "../models/proof";
import {ElGamal} from "../cryptography/elgamal";
import {Ballot, BallotConverter} from "../models/ballot";
import * as ecdsa from "../cryptography/ecdsa";
import {toJson} from "../utils";

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

    logger: any;

    constructor(keypair: lrs.KeyPair, scope: Array<string>, caster: Buffer, publicParameters: PublicParameters, logger?: any) {
        this.keypair = keypair;
        this.caster = caster;
        this.publicParameters = publicParameters;
        this.scope = scope;
        this.logger = logger;

        this.keys = new Array<eddsa.KeyPair>();
    }

    castVote(vote: Vote): CastedVote {
        this.logger?.verbose(`Casting vote ${vote}`);

        const pair = eddsa.generateKeypair();
        let sig = eddsa.sign(vote, pair.privateKey);

        // Check signature
        assert(eddsa.verify(vote, pair.publicKey, sig), "Invalid EdDSA MiMC-7 signature");

        this.keys.push(pair);

        const castedVote = {
            vote,
            sign: sig,
            pubKey: pair.publicKey
        };
        this.logger?.verbose(`Vote casted:\n${toJson(castedVote)}`);

        return castedVote;
    }

    async checkEncryptedBallot(ballot: EncryptedVote) {
        this.logger?.verbose(`Verifying encrypted vote`);
        await cesv.verifyProof(ballot.cesv.proof, ballot.cesv.publicSignals);
        this.logger?.verbose(`CESV Proof OK`);
        this.checkCesvInput(cesv.fromArray(ballot.cesv.publicSignals), ballot.vote);
        this.logger?.verbose(`CESV Input signals OK`);

        await cevi.verifyProof(ballot.cevi.proof, ballot.cevi.publicSignals);
        this.logger?.verbose(`CEVI Proof OK`);
        this.checkCeviInput(cevi.fromArray(ballot.cevi.publicSignals), ballot.vote);
        this.logger?.verbose(`CEVI Input signals OK`);
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
        this.logger?.verbose(`Signing ballot ${BallotConverter.toShortString(ballot)}`);
        const voteStr = BallotConverter.voteToHexString(ballot);
        ballot.voterSign = lrs.sign(voteStr, this.keypair, this.scope);

        assert(lrs.verify(voteStr, ballot.voterSign, this.scope), "Invalid Linkable Ring Signature");

        this.logger?.verbose(`Sign: ${ballot.voterSign}`);

        return ballot;
    }

    async verifyCasterSign(ballot: Ballot): Promise<void> {
        this.logger?.verbose(`Verifying caster sign of ballot ${BallotConverter.toShortString(ballot)}`);
        assert(await ecdsa.verify(BallotConverter.voteToHexString(ballot), this.caster, <ecdsa.Sign>ballot.casterSign), "Invalid Caster sign");
        this.logger?.verbose(`Caster sign OK`);
    }
}