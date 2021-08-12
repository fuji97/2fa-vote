import {Voter} from "../Voter";
import * as babyjubjub from "../babyjubjub";
import {PublicParameters, Vote} from "../types";
import * as eddsa from "../eddsa";
import assert from "assert";
import {Caster, CasterData} from "../Caster";
import {Authority} from "../Authority";
import {toJson} from "../utils";
import {decrypt, encrypt} from "../elgamal";
import {cevi, cesv} from "../proof";
import {generateKeypair} from "../lrs";
import * as ecdsa from "../ecdsa";
import {Verifier} from "../Verifier";

const bigInt = require("big-integer");
import {BallotConverter} from "../ballot";
import winston from "winston";

(async () => {
    try {
        const levels = {
            error: 0,
            warn: 1,
            info: 2,
            verbose: 3,
        };

        const colors = {
            error: 'red',
            warn: 'yellow',
            info: 'green',
            verbose: 'blue',
        };

        winston.addColors(colors);

        const transports = [
            // Allow the use the console to print the messages
            new winston.transports.Console()
        ];

        const format = winston.format.combine(
            // Add the message timestamp with the preferred format
            // Tell Winston that the logs must be colored
            winston.format.colorize({ level: true }),
            // Define the format of the message showing the timestamp, the level and the message
            winston.format.printf(
                (info) => `[${info.level}] ${info.message}`,
            )
        );

        const logger = winston.createLogger({
            level: 'verbose',
            levels,
            transports,
            format
        });

        const votingOptions: Vote[] = [1n, 2n];
        let authority = new Authority(babyjubjub.generateKeypair(), votingOptions, logger);

        const voters = [
            generateKeypair(),
            generateKeypair(),
            generateKeypair()
        ];
        const scope = voters.map(x => x.publicKey);

        let caster = new Caster(0, ecdsa.generateKeypair(), scope, authority.pp, logger);

        const castersData = new Map<number, CasterData>();
        castersData.set(caster.id, { publicKey: caster.keypair.publicKey, scope })

        let voter = new Voter(voters[0], scope, caster.keypair.publicKey, authority.pp, logger);

        let verifier = new Verifier(castersData, authority.pp, logger);

        // Add scope in authority
        authority.casters = castersData;

        let vote: Vote = 1n;
        let pointVote = babyjubjub.scalarToPoint(vote);

        // VOTER: Casting ballot
        logger.info("Voter creating and signing vote...")
        const ballot = voter.castVote(vote);
        logger.info("Ballot:")
        logger.info(toJson(vote));

        // CASTER: Checking and encrypting ballot
        logger.info("Caster encrypting and generating proofs...")
        const encryptedBallot = await caster.encryptVote(ballot.vote, ballot.pubKey, ballot.sign);
        logger.info("Encrypted Ballot:")
        logger.info(toJson(encryptedBallot));

        // VOTER: Checking and signing ballot
        logger.info("Voter checking and signing encrypted ballot...");
        await voter.checkEncryptedBallot(encryptedBallot);
        logger.info("Encrypted Ballot OK!")
        let signedBallot = BallotConverter.fromEncryptedVote(encryptedBallot);
        const strBallot = BallotConverter.voteToHexString(signedBallot);
        logger.info(strBallot);

        const rebuiltBallot = BallotConverter.fromString(strBallot, caster.id);
        logger.info(toJson(rebuiltBallot))
        const publicSignals = cevi.buildPublicInput(rebuiltBallot.vote, authority.pp);
        await cevi.verifyProof(rebuiltBallot.proof, cevi.toArray(publicSignals));
        logger.info("Proof OK!")

        signedBallot = voter.signBallot(signedBallot);
        logger.info("Ballot signed by Voter");
        caster.verifyVoterSign(signedBallot);
        logger.info("Voter LRS OK!");
        signedBallot = await caster.signBallot(signedBallot);
        logger.info("Ballot signed by Caster");
        await voter.verifyCasterSign(signedBallot);
        logger.info("Caster signature OK");
        caster.castBallot(signedBallot);
        logger.info("Ballot casted");

        // Verifier receiving and verifying ballot
        logger.info("Verifier receiving and verifying ballot...");
        await verifier.receiveBallot(signedBallot);
        logger.info("Verifier OK!");

        // Authority receiving and verifying ballot
        logger.info("Authority receiving and verifying ballot...");
        await authority.receiveBallot(signedBallot);
        logger.info("Authority OK!");

        // Authority tallying ballots
        const tally = authority.tally();
        logger.info("Tally complete! Result:");
        logger.info(toJson(Object.fromEntries(tally)));

        logger.info("Execution ended - All OK!");

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