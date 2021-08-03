import {EddsaSign} from "./eddsa";
import {Point, Axis} from "./types";
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
    proof: any;
    publicSignals: Array<Axis>;
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

export async function generateCesvProof(input: CesvInput): Promise<Proof> {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, CESV_CIRCUIT.wasm, CESV_CIRCUIT.zkey);
    return { proof, publicSignals };
}

export async function generateCeviProof(input: CeviInput): Promise<Proof> {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, CEVI_CIRCUIT.wasm, CEVI_CIRCUIT.zkey);
    return { proof, publicSignals };
}

export async function verifyCesvProof(proof: Proof): Promise<boolean> {
    return await snarkjs.groth16.verify(CESV_CIRCUIT.verificationKey, proof.publicSignals, proof.proof);
}

export async function verifyCeviProof(proof: Proof): Promise<boolean> {
    return await snarkjs.groth16.verify(CEVI_CIRCUIT.verificationKey, proof.publicSignals, proof.proof);
}