import {Scalar, PublicParameters} from "./types";
import {ElGamal} from "./elgamal";
// @ts-ignore
import * as snarkjs from "snarkjs";
import * as eddsa from "./eddsa";
import * as babyjubjub from "./babyjubjub";

type VerificationKey = any

type ProofInput = {
    wasm: string;
    zkey: string;
    verificationKey: VerificationKey;
}

const CESV_CIRCUIT: ProofInput = {
    wasm: "./out/correct_encrypt_signed_vote/circuit.wasm",
    zkey: "./out/correct_encrypt_signed_vote/circuit.zkey",
    verificationKey: require("../out/correct_encrypt_signed_vote/verification_key.json") as VerificationKey
}

const CEVI_CIRCUIT: ProofInput = {
    wasm: "./out/correct_encrypt_valid_input/circuit.wasm",
    zkey: "./out/correct_encrypt_valid_input/circuit.zkey",
    verificationKey: require("../out/correct_encrypt_valid_input/verification_key.json") as VerificationKey
}

type ElGamalPublicInput = {
    P: Array<Scalar>;
    B: Array<Scalar>;
    Y: Array<Scalar>;
}

type ElGamalInput = ElGamalPublicInput & {
    m: Scalar;
    k: Scalar;
}

type EddsaPublicInput = {
    pub: Array<Scalar>
}

type EddsaInput = EddsaPublicInput & {
    s: Scalar,
    R8: Array<Scalar>
}

type Output = {
    C: Array<Scalar>;
    D: Array<Scalar>;
}

export type CesvPublicInput = ElGamalPublicInput & EddsaPublicInput & Output
export type CesvInput = ElGamalInput & EddsaInput

export type CeviPublicInput = ElGamalPublicInput & Output
export type CeviInput = ElGamalInput

export type Proof = {
    pi_a: Array<string>;
    pi_b: Array<Array<string>>;
    pi_c: Array<string>;
    protocol: string;
    curve: string;
}

export type ProofSignals = {
    proof: Proof;
    publicSignals: Array<string>;
}

export const cesv = {
    generateProof: async function(input: CesvInput): Promise<ProofSignals> {
        const res = snarkjs.groth16.fullProve(input, CESV_CIRCUIT.wasm, CESV_CIRCUIT.zkey);
        const { proof, publicSignals } = await res;
        return { proof, publicSignals };
    },

    verifyProof: async function(proof: Proof, publicSignals: Array<string>): Promise<boolean> {
        return await snarkjs.groth16.verify(CESV_CIRCUIT.verificationKey, publicSignals, proof);
    },

    fromArray: function(arr: Array<string>): CesvPublicInput {
        const intArr = arr.map(x => BigInt(x));
        return {
            C: intArr.slice(0, 2),
            D: intArr.slice(2, 4),
            P: intArr.slice(4, 6),
            B: intArr.slice(6, 8),
            Y: intArr.slice(8, 10),
            pub: intArr.slice(10, 12)
        }
    },

    toArray: function(input: CesvPublicInput): Array<string> {
        const arr = [
            ...input.C,
            ...input.D,
            ...input.P,
            ...input.B,
            ...input.Y,
            ...input.pub,
        ];
        return arr.map(x => x.toString());
    },

    buildPublicInput: function(vote: ElGamal, pp: PublicParameters, pubKey: babyjubjub.PublicKey): CesvPublicInput {
        return {
            C: vote.C.toArray(),
            D: vote.D.toArray(),
            P: pp.elGamalPPoint.toArray(),
            B: pp.elGamalBasePoint.toArray(),
            Y: pp.authorityKey.toArray(),
            pub: pubKey.toArray()
        }
    }
}

export const cevi = {
    generateProof: async function(input: CeviInput): Promise<ProofSignals> {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, CEVI_CIRCUIT.wasm, CEVI_CIRCUIT.zkey);
        return { proof, publicSignals };
    },

    verifyProof: async function(proof: Proof, publicSignals: Array<string>): Promise<boolean> {
        return await snarkjs.groth16.verify(CEVI_CIRCUIT.verificationKey, publicSignals, proof);
    },

    fromArray: function(arr: Array<string>): CeviPublicInput {
        const intArr = arr.map(x => BigInt(x));
        return {
            C: intArr.slice(0, 2),
            D: intArr.slice(2, 4),
            P: intArr.slice(4, 6),
            B: intArr.slice(6, 8),
            Y: intArr.slice(8, 10),
        }
    },

    toArray: function(input: CeviPublicInput): Array<string> {
        const arr = [
            ...input.C,
            ...input.D,
            ...input.P,
            ...input.B,
            ...input.Y,
        ];
        return arr.map(x => x.toString());
    },

    buildPublicInput: function(vote: ElGamal, pp: PublicParameters): CeviPublicInput {
        return {
            C: vote.C.toArray(),
            D: vote.D.toArray(),
            P: pp.elGamalPPoint.toArray(),
            B: pp.elGamalBasePoint.toArray(),
            Y: pp.authorityKey.toArray()
        }
    }
}