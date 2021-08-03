import {Voter} from "./Voter";
import {Base8, pointFromArray, randomScalar} from "./babyjubjub";
import {Point, PublicParameters} from "./types";
import {EddsaSign, generateKeypair, verify} from "./eddsa";
import assert from "assert";

const eddsa = require("circomlib").eddsa;
const mimc = require("circomlib").mimc7;
const bigInt = require("big-integer");

const pp: PublicParameters = {
    authorityKey: Base8,

}

let voter = new Voter(generateKeypair(), pp);

console.log(voter.castVote(1n));

// const preimage = 10n;
// const key = 1684557355573270755209121427403383784906688334546342811893263215061668769545n;
//
// const M = 1n;
// const bigPriv = randomScalar()
// const prvKey = Buffer.from(bigPriv.toString(16), "hex");
// const pubKey = eddsa.prv2pub(prvKey);
// const pointPub = pointFromArray(pubKey);
//
// const signature = eddsa.signMiMC(prvKey, M);
//
// const parsedSig: EddsaSign = {
//     R8: pointFromArray(signature.R8),
//     S: signature.S
// }
//
// assert(eddsa.verifyMiMC(M, { R8: parsedSig.R8.toArray(), S: parsedSig.S }, pointPub.toArray()));