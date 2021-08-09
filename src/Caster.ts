import {PublicParameters, Vote, Scalar, Scope} from "./types";
import {CesvInput, CeviInput, cesv, cevi, ProofSignals} from "./proof";
import {Base8, randomScalar} from "./babyjubjub";
import {ElGamal} from "./elgamal";
import {Ballot, BallotConverter} from "./ballot";
import * as BabyJub from "./babyjubjub";
import * as eddsa from "./eddsa";
import * as lrs from "./lrs";
import * as ecdsa from "./ecdsa";
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

    constructor(id: number, keypair: ecdsa.KeyPair, scope: Scope, publicParameters: PublicParameters) {
        this.id = id;
        this.keypair = keypair;
        this.publicParameters = publicParameters;
        this.scope = scope;

        this.signatures = new Array<lrs.Sign>();
    }

    async encryptVote(vote: Vote, pubKey: eddsa.PublicKey, sign: eddsa.Sign, k?: Scalar): Promise<EncryptedVote> {
        // Generate k
        k = k ?? randomScalar();

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
        }

        // Create proof
        const cesvProof = await cesv.generateProof(cesvInput);

        // Check proof
        assert(await cesv.verifyProof(cesvProof.proof, cesvProof.publicSignals), "Invalid CESV Proof");
        //console.log("Valid CESV Proof!");

        // Create CEVI Input
        const ceviInput: CeviInput = {
            B: Base8.toArray(),
            P: Base8.toArray(),
            Y: this.publicParameters.authorityKey.toArray(),
            k: k!,
            m: vote
        }

        // Create proof
        const ceviProof = await cevi.generateProof(ceviInput);

        // Check proof
        assert(await cevi.verifyProof(ceviProof.proof, ceviProof.publicSignals), "Invalid CEVI Proof");
        //console.log("Valid CEVI Proof!");

        return {
            vote: {
                C: BabyJub.Point.fromArray(ceviProof.publicSignals.slice(0,2).map((x) => BigInt(x))),
                D: BabyJub.Point.fromArray(ceviProof.publicSignals.slice(2,4).map((x) => BigInt(x)))
            },
            cesv: cesvProof,
            cevi: ceviProof,
            caster: this.id
        }
    }

    verifyVoterSign(ballot: Ballot): void {
        assert(lrs.verify(BallotConverter.voteToHexString(ballot), <lrs.Sign>ballot.voterSign, this.scope),
            "Invalid Linkable Ring Signature");

        // Verify links
        for (const sig in this.signatures) {
            assert(!lrs.link(<lrs.Sign>ballot.voterSign, sig), "Double signature detected!");
        }
    }

    async signBallot(ballot: Ballot): Promise<Ballot> {
        const msg = BallotConverter.voteToHexString(ballot);
        const sign = await ecdsa.sign(msg, this.keypair.privateKey);

        await ecdsa.verify(msg, this.keypair.publicKey, sign);

        ballot.casterSign = sign;
        return ballot;
    }

    castBallot(ballot: Ballot): void {
        this.signatures.push(<lrs.Sign>ballot.voterSign);
    }
}