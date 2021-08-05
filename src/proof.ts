import {EddsaSign} from "./eddsa";
import {Point, Axis, PublicParameters, PublicKey} from "./types";
import {ElGamal} from "./elgamal";
const snarkjs = require("snarkjs");

type VerificationKey = any

type ProofInput = {
    wasm: string;
    zkey: string;
    verificationKey: VerificationKey
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

export type SignedVote = {
    vote: number;
    sign: EddsaSign
}

type ElGamalPublicInput = {
    P: Array<Axis>;
    B: Array<Axis>;
    Y: Array<Axis>;
}

type ElGamalInput = ElGamalPublicInput & {
    m: Axis;
    k: Axis;
}

type EddsaPublicInput = {
    pub: Array<Axis>
}

type EddsaInput = EddsaPublicInput & {
    s: Axis,
    R8: Array<Axis>
}

type Output = {
    C: Array<Axis>;
    D: Array<Axis>;
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

// class ProofPublicDataLoader {
//     private static _cesvVerKey: VerificationKey;
//     private static _ceviVerKey: VerificationKey;
//
//     get cesvVerKey {
//         if (ProofPublicDataLoader._cesvVerKey == null) {
//
//         }
//     }
//
//
// }

export async function generateCesvProof(input: CesvInput): Promise<ProofSignals> {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, CESV_CIRCUIT.wasm, CESV_CIRCUIT.zkey);
    return { proof, publicSignals };
}

export async function generateCeviProof(input: CeviInput): Promise<ProofSignals> {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, CEVI_CIRCUIT.wasm, CEVI_CIRCUIT.zkey);
    return { proof, publicSignals };
}

export async function verifyCesvProof(proof: Proof, publicSignals: Array<string>): Promise<boolean> {
    return await snarkjs.groth16.verify(CESV_CIRCUIT.verificationKey, publicSignals, proof);
}

export async function verifyCeviProof(proof: Proof, publicSignals: Array<string>): Promise<boolean> {
    return await snarkjs.groth16.verify(CEVI_CIRCUIT.verificationKey, publicSignals, proof);
}

export class CesvInputConverter {
    static fromArray(arr: Array<string>): CesvPublicInput {
        const intArr = arr.map(x => BigInt(x));
        return {
            C: intArr.slice(0, 2),
            D: intArr.slice(2, 4),
            P: intArr.slice(4, 6),
            B: intArr.slice(6, 8),
            Y: intArr.slice(8, 10),
            pub: intArr.slice(10, 12)
        }
    }

    static toArray(input: CesvPublicInput): Array<string> {
        const arr = [
            ...input.C,
            ...input.D,
            ...input.P,
            ...input.B,
            ...input.Y,
            ...input.pub,
        ];
        return arr.map(x => x.toString());
    }
}

export class CeviInputConverter {
    static fromArray(arr: Array<string>): CeviPublicInput {
        const intArr = arr.map(x => BigInt(x));
        return {
            C: intArr.slice(0, 2),
            D: intArr.slice(2, 4),
            P: intArr.slice(4, 6),
            B: intArr.slice(6, 8),
            Y: intArr.slice(8, 10),
        }
    }

    static toArray(input: CeviPublicInput): Array<string> {
        const arr = [
            ...input.C,
            ...input.D,
            ...input.P,
            ...input.B,
            ...input.Y,
        ];
        return arr.map(x => x.toString());
    }
}

export function buildCeviPublicInput(vote: ElGamal, pp: PublicParameters): CeviPublicInput {
    return {
        C: vote.C.toArray(),
        D: vote.D.toArray(),
        P: pp.elGamalPPoint.toArray(),
        B: pp.elGamalBasePoint.toArray(),
        Y: pp.authorityKey.toArray()
    }
}

export function buildCesvPublicInput(vote: ElGamal, pp: PublicParameters, pubKey: PublicKey): CesvPublicInput {
    return {
        C: vote.C.toArray(),
        D: vote.D.toArray(),
        P: pp.elGamalPPoint.toArray(),
        B: pp.elGamalBasePoint.toArray(),
        Y: pp.authorityKey.toArray(),
        pub: pubKey.toArray()
    }
}