import {KeyPair, PublicKey, PublicParameters, Vote, Point} from "./types";
import * as BabyJub from "./babyjubjub";
import {EddsaSign} from "./eddsa";
import {
    CesvInput, CesvPublicInput,
    CeviInput, CeviPublicInput,
    generateCesvProof,
    generateCeviProof,
    Proof,
    verifyCesvProof,
    verifyCeviProof
} from "./proof";
import {Base8, Generator, randomScalar} from "./babyjubjub";
import assert from "assert";
import {ElGamal} from "./elgamal";

export type EncryptedVote = {
    vote: ElGamal,
    cesv: Proof<CesvPublicInput>,
    cevi: Proof<CeviPublicInput>
}

export class Caster {
    keypair: KeyPair;
    publicParameters: PublicParameters;


    constructor(keypair: KeyPair, publicParameters: PublicParameters) {
        this.keypair = keypair;
        this.publicParameters = publicParameters;
    }

    async encryptVote(vote: Vote, pubKey: PublicKey, sign: EddsaSign): Promise<EncryptedVote> {
        // Generate k
        const k = randomScalar();

        // Create CESV Input
        const cesvInput: CesvInput = {
            B: Base8.toArray(),
            P: Generator.toArray(),
            R8: sign.R8.toArray(),
            Y: this.keypair.publicKey.toArray(),
            k: k,
            m: vote,
            pub: pubKey.toArray(),
            s: sign.S
        }

        // Create proof
        const cesv = await generateCesvProof(cesvInput);

        // Check proof
        assert(await verifyCesvProof(cesv), "Invalid CESV Proof");

        // Create CEVI Input
        const ceviInput: CeviInput = {
            B: Base8.toArray(),
            P: Generator.toArray(),
            Y: this.keypair.publicKey.toArray(),
            k: k,
            m: vote
        }

        // Create proof
        const cevi = await generateCeviProof(ceviInput);

        // Check proof
        assert(await verifyCeviProof(cevi), "Invalid CEVI Proof");

        return {
            vote: {
                C: BabyJub.Point.fromArray(cesv.publicSignals.C),
                D: BabyJub.Point.fromArray(cesv.publicSignals.D)
            }, // TODO
            cesv: cesv,
            cevi: cevi
        }
    }
}