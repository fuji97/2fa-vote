import {generateLrsKeypair} from "../lrs";
import * as lrs from "../lrs";
import assert from "assert";

(async () => {
    try {

        const voters = [
            generateLrsKeypair(),
            generateLrsKeypair(),
            generateLrsKeypair()
        ];
        const scope = voters.map(x => x.publicKey);

        const message = "This is the message";

        const sig = lrs.sign(message, voters[0], scope);
        assert(lrs.verify(message, sig, scope), "Invalid Linkable Ring Signature");

    } catch (e) {
        //console.error(e);
        throw e;
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
// assert(eddsa.verifyMiMC(M, { R8: parsedSig.R8.toArray(), S: parsedSig.S }, pointPub.toArray()));