import {PublicParameters} from "./types";
import {cevi, Proof} from "./proof";
import {CasterData, EncryptedVote} from "./Caster";
import {bigintToBuf, bufToBigint, TypedArray} from "bigint-conversion";
import assert from "assert";
import {ElGamal} from "./elgamal";
import * as babyjub from "./babyjubjub";
import * as ecdsa from "./ecdsa";
import * as lrs from "./lrs";

export type Ballot = {
    vote: ElGamal,
    proof: Proof,
    caster: number,
    voterSign?: lrs.Sign;
    casterSign?: ecdsa.Sign;
};

export const BallotConverter = {
    voteToHexString(ballot: Ballot): string {
        let arr = [...ballot.vote.C.pack(), ...ballot.vote.D.pack()];
        arr = [...arr, ...serializeProof(ballot.proof)];

        return Buffer.from([...arr]).toString('hex');
    },

    fromString(str: string, caster: number): Ballot {
        const buf = Buffer.from(str, 'hex');
        assert(buf.length === 32*14);
        const splits = split32(buf);

        return {
            vote: {
                C: babyjub.Point.unpack(splits[0]),
                D: babyjub.Point.unpack(splits[1])
            },
            caster: caster,
            proof: {
                pi_a: [
                    bufferToBigInt(splits[2]).toString(),
                    bufferToBigInt(splits[3]).toString(),
                    bufferToBigInt(splits[4]).toString()
                ],
                pi_b: [
                    [bufferToBigInt(splits[5]).toString(),bufferToBigInt(splits[6]).toString()],
                    [bufferToBigInt(splits[7]).toString(),bufferToBigInt(splits[8]).toString()],
                    [bufferToBigInt(splits[9]).toString(),bufferToBigInt(splits[10]).toString()]
                ],
                pi_c: [
                    bufferToBigInt(splits[11]).toString(),
                    bufferToBigInt(splits[12]).toString(),
                    bufferToBigInt(splits[13]).toString()
                ],
                protocol: "groth16",
                curve: "bn128"
            }
        }
    },

    fromEncryptedVote(vote: EncryptedVote): Ballot {
        return {
            vote: vote.vote,
            proof: vote.cevi.proof,
            caster: vote.caster
        }
    },
}

function serializeProof(proof: Proof): Uint8Array {
    const all = [...proof.pi_a, ...proof.pi_b, ...proof.pi_c].flat();
    const nums = all.map(x => Uint8Array.from(bigIntToBuffer32(BigInt(x))));
    return Uint8Array.from(nums.map(typedArray => [...new Uint8Array(typedArray.buffer)]).flat());
}

export function bigIntToBuffer32(num: bigint): Uint8Array {
    const numBuf = bigintToBuf(num);
    assert(numBuf.byteLength <= 32, "BigInt too big");

    const b = Buffer.alloc(32);
    // @ts-ignore
    numBuf.copy(b, b.length - numBuf.byteLength);

    return b;
}

export function bufferToBigInt(buf: ArrayBuffer | TypedArray | Buffer): bigint {
    return bufToBigint(buf);
}

function split32(buf: Buffer): Array<Buffer> {
    let splits: Array<Buffer> = [];
    for (let i = 0; i < buf.length / 32; i++) {
        splits.push(buf.slice(i*32, (i+1)*32));
    }
    return splits;
}

export async function verifyBallot(ballot: Ballot, casterData: CasterData, scopedBallots: Ballot[] | undefined, pp: PublicParameters): Promise<void> {
    const payload = BallotConverter.voteToHexString(ballot);

    // Check Caster sign
    await ecdsa.verify(payload, casterData.publicKey, <ecdsa.Sign>ballot.casterSign);

    // Check Voter Linkable Ring Signature
    lrs.verify(payload, <lrs.Sign>ballot.voterSign, casterData.scope);
    if (scopedBallots != undefined) {
        for (const scopeBallot of scopedBallots) {
            assert(!lrs.link(ballot.voterSign!, scopeBallot.voterSign!), "Double signature found");
        }
    }

    // Check proofs
    const publicSignals = cevi.buildPublicInput(ballot.vote, pp);
    assert(await cevi.verifyProof(ballot.proof, cevi.toArray(publicSignals)),
        "Invalid CEVI proof");
}