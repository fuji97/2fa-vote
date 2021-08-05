/*
import {Voter} from "./Voter";
import {Base8, generateKeypair, scalarToPoint} from "./babyjubjub";
import {PublicParameters, Vote} from "./types";
import {generateEddsaKeypair} from "./eddsa";
import assert from "assert";
import {Caster} from "./Caster";
import {Authority} from "./Authority";
import {toJson} from "./utils";
import {decrypt, encrypt} from "./elgamal";

const eddsa = require("circomlib").eddsa;
const mimc = require("circomlib").mimc7;
const bigInt = require("big-integer");

(async () => {
    try {
        let authority = new Authority(generateKeypair());
        let voter = new Voter(generateEddsaKeypair(), authority.pp);
        let caster = new Caster(generateKeypair(), authority.pp);

        let vote: Vote = 1n;
        let pointVote = scalarToPoint(vote);

        console.log("Voter creating and signing vote...")
        const ballot = voter.castVote(vote);
        //console.log(vote);

        console.log("\n Caster encrypting and generating proofs...")
        const encryptedBallot = await caster.encryptVote(ballot.vote, ballot.pubKey, ballot.sign);

        const testEncrypt = encrypt(pointVote, authority.pp.authorityKey, caster.lastUsedK);
        const testEncrypt2 = encrypt(pointVote, authority.pp.authorityKey, caster.lastUsedK);

        // Test procedural encryption
        console.log("\nEncrypted ballots comparison:");
        console.log("Encrypted ballot from proof:")
        console.log(toJson(encryptedBallot));

        console.log("Manual encrypted ballot:")
        console.log(toJson(testEncrypt))

        assert(testEncrypt.C.equals(testEncrypt2.C) && testEncrypt.D.equals(testEncrypt2.D), "Not a procedural encryption");

        // Test decryption
        const testDecrypt = decrypt(testEncrypt, authority.keypair.privateKey);
        assert(testDecrypt.equals(pointVote), "Encryption/decryption wrong");

        // Test encrypted ballot
        assert(encryptedBallot.vote.C.equals(testEncrypt.C) && encryptedBallot.vote.D.equals(testEncrypt.D), "Encrypted ballots are different");

        const decryptedBallot = authority.decrypt(encryptedBallot.vote);

        console.log("\nCompare votes:")
        console.log(pointVote.toString());
        console.log(decryptedBallot.toString());
        assert(decryptedBallot.equals(pointVote), "Encrypted point and decrypted point are different");

    } catch (e) {
        console.error(e);
    }
})();



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
// assert(eddsa.verifyMiMC(M, { R8: parsedSig.R8.toArray(), S: parsedSig.S }, pointPub.toArray()));*/
