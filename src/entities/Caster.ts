import {PublicParameters, Vote, Scalar, Scope} from "../models/types";
import {CesvInput, CeviInput, cesv, cevi, ProofSignals} from "../models/proof";
import {Base8, randomScalar} from "../cryptography/babyjubjub";
import {ElGamal} from "../cryptography/elgamal";
import {Ballot, BallotConverter} from "../models/ballot";
import * as BabyJub from "../cryptography/babyjubjub";
import * as eddsa from "../cryptography/eddsa";
import * as lrs from "../cryptography/lrs";
import * as ecdsa from "../cryptography/ecdsa";
import assert from "assert";

export type CasterData = {
    scope: Scope;
    publicKey: Buffer;
}

export type EncryptedVote = {
    vote: ElGamal,
    cesv: ProofSignals,
    cevi: ProofSignals,
    caster: number
}

export class Caster {
    keypair: ecdsa.KeyPair;
    publicParameters: PublicParameters;
    scope: Scope;
    id: number;
    signatures: Array<lrs.Sign>;

    logger: any;

    constructor(id: number, keypair: ecdsa.KeyPair, scope: Scope, publicParameters: PublicParameters, logger?: any) {
        this.id = id;
        this.keypair = keypair;
        this.publicParameters = publicParameters;
        this.scope = scope;
        this.logger = logger;

        this.signatures = new Array<lrs.Sign>();
    }

    async encryptVote(vote: Vote, pubKey: eddsa.PublicKey, sign: eddsa.Sign, k?: Scalar): Promise<EncryptedVote> {
        // Generate k
        k = k ?? randomScalar();

        this.logger?.verbose(`Encrypting vote ${vote}`);

        // Create CESV Input
        const cesvInput: CesvInput = {
            B: Base8.toArray(),
            P: Base8.toArray(),
            R8: sign.R8.toArray(),
            Y: this.publicParameters.authorityKey.toArray(),
            k: k!,
            m: vote,
            pub: pubKey.toArray(),
            s: sign.S
        };


        // Create proof
        this.logger?.verbose(`Generating CESV proof...`);
        const cesvProof = await cesv.generateProof(cesvInput);

        // Check proof
        this.logger?.verbose(`Verifying CESV proof...`);
        assert(await cesv.verifyProof(cesvProof.proof, cesvProof.publicSignals), "Invalid CESV Proof");
        this.logger?.verbose(`CESV proof OK`);

        // Create CEVI Input
        const ceviInput: CeviInput = {
            B: Base8.toArray(),
            P: Base8.toArray(),
            Y: this.publicParameters.authorityKey.toArray(),
            k: k!,
            m: vote
        };

        // Create proof
        this.logger?.verbose(`Generating CEVI proof...`);
        const ceviProof = await cevi.generateProof(ceviInput);

        // Check proof
        this.logger?.verbose(`Verifying CEVI proof...`);
        assert(await cevi.verifyProof(ceviProof.proof, ceviProof.publicSignals), "Invalid CEVI Proof");
        this.logger?.verbose(`CEVI proof OK`);

        return {
            vote: {
                C: BabyJub.Point.fromArray(ceviProof.publicSignals.slice(0,2).map((x) => BigInt(x))),
                D: BabyJub.Point.fromArray(ceviProof.publicSignals.slice(2,4).map((x) => BigInt(x)))
            },
            cesv: cesvProof,
            cevi: ceviProof,
            caster: this.id
        };
    }

    verifyVoterSign(ballot: Ballot): void {
        this.logger?.verbose(`Verifying ballot ${BallotConverter.toShortString(ballot)}`);

        assert(lrs.verify(BallotConverter.voteToHexString(ballot), <lrs.Sign>ballot.voterSign, this.scope),
            "Invalid Linkable Ring Signature");

        // Verify links
        for (const sig in this.signatures) {
            assert(!lrs.link(<lrs.Sign>ballot.voterSign, sig), "Double signature detected!");
        }
        this.logger?.verbose(`Ballot ${BallotConverter.toShortString(ballot)} OK`);
    }

    async signBallot(ballot: Ballot): Promise<Ballot> {
        this.logger?.verbose(`Signing ballot ${BallotConverter.toShortString(ballot)}`);
        const msg = BallotConverter.voteToHexString(ballot);
        const sign = await ecdsa.sign(msg, this.keypair.privateKey);

        await ecdsa.verify(msg, this.keypair.publicKey, sign);
        this.logger?.verbose(`Sign: ${sign}`);

        ballot.casterSign = sign;
        return ballot;
    }

    castBallot(ballot: Ballot): void {
        this.logger?.verbose(`Casting ballot ${BallotConverter.toShortString(ballot)}`);
        this.signatures.push(<lrs.Sign>ballot.voterSign);
    }
}