import {decrypt, encrypt} from "../elgamal";
import {Base8, randomScalar} from "../babyjubjub";
import {toJson} from "../utils";
import assert from "assert";
import {CesvInput, CeviInput, generateCesvProof, generateCeviProof} from "../proof";

const eddsa = require("../../node_modules/circomlib").eddsa;
const mimc = require("../../node_modules/circomlib").mimc7;
const bigInt = require("big-integer");

(async () => {
    try {
        let sk = 49565234564307524635023457n;
        let pk = Base8.mulScalar(sk);
        let vote = 1n;
        let pointToEncrypt = Base8.mulScalar(1n);
        let k = 3455764305672345643275647356n;

        let enc = encrypt(pointToEncrypt, pk, k);
        let dec = decrypt(enc, sk);

        console.log("Encrypted value:");
        console.log(toJson(enc));

        console.log("\nCompare original values:");
        console.log(pointToEncrypt.toString());
        console.log(dec.toString());

        assert(dec.equals(pointToEncrypt), "Wrong encryption or decryption");

        console.log("\nEncrypting via proof: ");
        const ceviInput: CeviInput = {
            B: Base8.toArray(),
            P: Base8.toArray(), // TODO Choose if to use Generator or Base8
            Y: pk.toArray(),
            k: k,
            m: vote,
        }

        // Create proof
        const cevi = await generateCeviProof(ceviInput);
        console.log(toJson(cevi.publicSignals));

    } catch (e) {
        console.error(e);
    }
})();