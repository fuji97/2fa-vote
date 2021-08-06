import {Voter} from "../Voter";
import {Base8, generateKeypair, scalarToPoint} from "../babyjubjub";
import {PublicParameters, Vote} from "../types";
import {generateEddsaKeypair} from "../eddsa";
import assert from "assert";
import {Caster, CasterData} from "../Caster";
import {Authority} from "../Authority";
import {toJson} from "../utils";
import {decrypt, encrypt} from "../elgamal";
import {buildCeviPublicInput, CeviInputConverter, verifyCeviProof} from "../proof";
import {generateLrsKeypair} from "../lrs";
import * as ecdsa from "../ecdsa";
import {Verifier} from "../Verifier";

const eddsa = require("../../node_modules/circomlib").eddsa;
const mimc = require("../../node_modules/circomlib").mimc7;
const bigInt = require("big-integer");
const BallotConverter = require("../ballot").BallotConverter;

(async () => {
    try {
        const votingOptions: Vote[] = [1n, 2n];
        let authority = new Authority(generateKeypair(), votingOptions);

        const voters = [
            generateLrsKeypair(),
            generateLrsKeypair(),
            generateLrsKeypair()
        ];
        const scope = voters.map(x => x.publicKey);

        let caster = new Caster(0, ecdsa.generateKeypair(), scope, authority.pp);

        const castersData = new Map<number, CasterData>();
        castersData.set(caster.id, { publicKey: caster.keypair.publicKey, scope })

        let voter = new Voter(voters[0], scope, caster.keypair.publicKey, authority.pp);

        let verifier = new Verifier(castersData, authority.pp);

        // Add scope in authority
        authority.casters = castersData;

        let vote: Vote = 1n;
        let pointVote = scalarToPoint(vote);

        // VOTER: Casting ballot
        console.log("Voter creating and signing vote...")
        const ballot = voter.castVote(vote);
        console.log("Ballot:")
        console.log(toJson(vote));

        // CASTER: Checking and encrypting ballot
        console.log("\nCaster encrypting and generating proofs...")
        const encryptedBallot = await caster.encryptVote(ballot.vote, ballot.pubKey, ballot.sign);
        console.log("Encrypted Ballot:")
        console.log(toJson(encryptedBallot));

        // VOTER: Checking and signing ballot
        console.log("\nVoter checking and signing encrypted ballot...");
        await voter.checkEncryptedBallot(encryptedBallot);
        console.log("Encrypted Ballot OK!")
        let signedBallot = BallotConverter.fromEncryptedVote(encryptedBallot);
        const strBallot = BallotConverter.voteToHexString(signedBallot);
        console.log(strBallot);

        const rebuiltBallot = BallotConverter.fromString(strBallot, signedBallot.proof.publicSignals);
        console.log(toJson(rebuiltBallot))
        const publicSignals = buildCeviPublicInput(rebuiltBallot.vote, authority.pp);
        await verifyCeviProof(rebuiltBallot.proof, CeviInputConverter.toArray(publicSignals));
        console.log("Proof OK!")

        signedBallot = voter.signBallot(signedBallot);
        console.log("Ballot signed by Voter");
        caster.verifyVoterSign(signedBallot);
        console.log("Voter LRS OK!");
        signedBallot = await caster.signBallot(signedBallot);
        console.log("Ballot signed by Caster");
        await voter.verifyCasterSign(signedBallot);
        console.log("Caster signature OK");
        caster.castBallot(signedBallot);
        console.log("Ballot casted");

        // Verifier receiving and verifying ballot
        console.log("\nVerifier receiving and verifying ballot...");
        await verifier.receiveBallot(signedBallot);
        console.log("Verifier OK!");

        // Authority receiving and verifying ballot
        console.log("\nAuthority receiving and verifying ballot...");
        await authority.receiveBallot(signedBallot);
        console.log("Authority OK!");

        // Authority tallying ballots
        const tally = authority.tally();
        console.log("Tally complete! Result:");
        console.log(toJson(tally));

        console.log("Execution ended - All OK!");

    } catch (e) {
        //console.error(e);
        throw e;
    }
})().then(() => process.exit(0));



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