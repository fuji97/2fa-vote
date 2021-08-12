import {PublicParameters, Vote, Point} from "./types";
import {CasterData} from "./Caster";
import {firstFromMap} from "./utils";
import * as babyjubjub from "./babyjubjub";
import * as elgamal from "./elgamal";
import * as ballots from "./ballot";
import assert from "assert";
import {BallotConverter} from "./ballot";

export class Authority {
    pp: PublicParameters;
    keypair: babyjubjub.KeyPair;
    voters: Array<babyjubjub.PublicKey>;
    casters: Map<number, CasterData>;
    ballots: Map<number, Array<ballots.Ballot>>;

    logger: any;

    constructor(keypair: babyjubjub.KeyPair, votingOptions: Vote[], logger?: any) {
        this.keypair = keypair;
        this.pp = {
            authorityKey: this.keypair.publicKey,
            elGamalBasePoint: babyjubjub.Base8,
            elGamalPPoint: babyjubjub.Base8,
            votingOptions: votingOptions
        };
        this.logger = logger;

        this.voters = new Array<babyjubjub.PublicKey>();
        this.casters = new Map<number, CasterData>();
        this.ballots = new Map<number, Array<ballots.Ballot>>();
    }

    private decrypt(enc: elgamal.ElGamal): Point {
        return elgamal.decrypt(enc, this.keypair.privateKey);
    }

    async receiveBallot(ballot: ballots.Ballot): Promise<void> {
        this.logger?.verbose(`Receiving ballot ${BallotConverter.toShortString(ballot)}`);
        await this.verifyBallot(ballot);

        if (!this.ballots.has(ballot.caster)) {
            this.ballots.set(ballot.caster, new Array<ballots.Ballot>());
        }
        this.ballots.get(ballot.caster)!.push(ballot);
    }

    private async verifyBallot(ballot: ballots.Ballot): Promise<void> {
        const data = this.casters.get(ballot.caster);
        assert(data != undefined, "Invalid Caster ID");

        const scopedBallots = this.ballots.get(ballot.caster);

        await ballots.verifyBallot(ballot, data, scopedBallots, this.pp);
        this.logger?.verbose(`Ballot ${BallotConverter.toShortString(ballot)} OK`);
    }

    tally(): Map<Vote, number> {
        this.logger?.verbose(`Tallying ${this.ballots.size} ballots`);

        const pointMap = this.buildPointMap();
        const voteMap = new Map<Vote, number>();

        for (const option of this.pp.votingOptions) {
            voteMap.set(option, 0);
        }

        for (const scopeBallots of this.ballots.values()) {
            for (const ballot of scopeBallots) {
                const dec = this.decrypt(ballot.vote);

                const vote = firstFromMap(pointMap, (key, val) => dec.equals(key));
                assert(vote != undefined, "Invalid vote");
                this.logger?.verbose(`Ballot ${BallotConverter.toShortString(ballot)} voted for ${vote}`);
                voteMap.set(vote, voteMap.get(vote)! + 1);
            }
        }

        return voteMap;
    }

    private buildPointMap(): Map<Point, Vote> {
        const pointMap = new Map<Point, Vote>();

        for (const option of this.pp.votingOptions) {
            pointMap.set(babyjubjub.Base8.mulScalar(option), option);
        }

        return pointMap;
    }
}