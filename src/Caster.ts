import {KeyPair, PublicKey, PublicParameters, Vote, Point, Axis, Scope} from "./types";
import * as BabyJub from "./babyjubjub";
import {EddsaSign} from "./eddsa";
import {
    CesvInput, CesvPublicInput,
    CeviInput, CeviPublicInput,
    generateCesvProof,
    generateCeviProof,
    ProofSignals,
    verifyCesvProof,
    verifyCeviProof
} from "./proof";
import {Base8, Generator, randomScalar} from "./babyjubjub";
import assert from "assert";
import {ElGamal} from "./elgamal";
import {toJson} from "./utils";
import {Ballot, BallotConverter} from "./ballot";
import * as lrs from "./lrs";
import {LrsSign} from "./lrs";
import * as ecdsa from "./ecdsa";

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
    lastUsedK: Axis;    // TODO Remove
    scope: Scope;
    id: number;
    signatures: Array<LrsSign>;

    constructor(id: number, keypair: ecdsa.KeyPair, scope: Scope, publicParameters: PublicParameters) {
        this.id = id;
        this.keypair = keypair;
        this.publicParameters = publicParameters;
        this.lastUsedK = -1n;
        this.scope = scope;

        this.signatures = new Array<LrsSign>();
    }

    async encryptVote(vote: Vote, pubKey: PublicKey, sign: EddsaSign): Promise<EncryptedVote> {
        // Generate k
        const k = randomScalar();
        this.lastUsedK = k;

        // Create CESV Input
        const cesvInput: CesvInput = {
            B: Base8.toArray(),
            P: Base8.toArray(), // TODO Choose if to use Generator or Base8
            R8: sign.R8.toArray(),
            Y: this.publicParameters.authorityKey.toArray(),
            k: k,
            m: vote,
            pub: pubKey.toArray(),
            s: sign.S
        }

        // Create proof
        const cesv = await generateCesvProof(cesvInput);

        // Check proof
        assert(await verifyCesvProof(cesv.proof, cesv.publicSignals), "Invalid CESV Proof");
        //console.log("Valid CESV Proof!");

        // Create CEVI Input
        const ceviInput: CeviInput = {
            B: Base8.toArray(),
            P: Base8.toArray(),
            Y: this.publicParameters.authorityKey.toArray(),
            k: k,
            m: vote
        }

        // Create proof
        const cevi = await generateCeviProof(ceviInput);

        // Check proof
        assert(await verifyCeviProof(cevi.proof, cevi.publicSignals), "Invalid CEVI Proof");
        //console.log("Valid CEVI Proof!");

        return {
            vote: {
                C: BabyJub.Point.fromArray(cevi.publicSignals.slice(0,2).map((x) => BigInt(x))),
                D: BabyJub.Point.fromArray(cevi.publicSignals.slice(2,4).map((x) => BigInt(x)))
            },
            cesv: cesv,
            cevi: cevi,
            caster: this.id
        }
    }

    verifyVoterSign(ballot: Ballot): void {
        assert(lrs.verify(BallotConverter.voteToHexString(ballot), <LrsSign>ballot.voterSign, this.scope),
            "Invalid Linkable Ring Signature");

        // Verify links
        for (const sig in this.signatures) {
            assert(!lrs.link(<LrsSign>ballot.voterSign, sig), "Double signature detected!");
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
        this.signatures.push(<LrsSign>ballot.voterSign);
    }
}