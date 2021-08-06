import {KeyPair, PublicParameters, Axis, Scope, Vote} from "./types";
import {Point} from "./types";
import {Base8} from "./babyjubjub";
import {decrypt, ElGamal} from "./elgamal";
import {CasterData} from "./Caster";
import {Ballot, verifyBallot} from "./ballot";
import assert from "assert";
import {firstFromMap} from "./utils";

type PublicKey = Point;

export class Authority {
    pp: PublicParameters;
    keypair: KeyPair;
    voters: Array<PublicKey>;
    casters: Map<number, CasterData>;
    ballots: Map<number, Array<Ballot>>;

    constructor(keypair: KeyPair, votingOptions: Vote[]) {
        this.keypair = keypair;
        this.pp = {
            authorityKey: this.keypair.publicKey,
            elGamalBasePoint: Base8,
            elGamalPPoint: Base8,
            votingOptions: votingOptions
        };

        this.voters = new Array<Point>();
        this.casters = new Map<number, CasterData>();
        this.ballots = new Map<number, Array<Ballot>>();
    }

    private decrypt(enc: ElGamal): Point {
        return decrypt(enc, this.keypair.privateKey);
    }

    async receiveBallot(ballot: Ballot): Promise<void> {
        await this.verifyBallot(ballot);

        if (!this.ballots.has(ballot.caster)) {
            this.ballots.set(ballot.caster, new Array<Ballot>());
        }
        this.ballots.get(ballot.caster)!.push(ballot);
    }

    private async verifyBallot(ballot: Ballot): Promise<void> {
        const data = this.casters.get(ballot.caster);
        assert(data != undefined, "Invalid Caster ID");

        const ballots = this.ballots.get(ballot.caster);

        await verifyBallot(ballot, data, ballots, this.pp);
    }

    tally(): Map<Vote, number> {
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
                voteMap.set(vote, voteMap.get(vote)! + 1);
            }
        }

        return voteMap;
    }

    private buildPointMap(): Map<Point, Vote> {
        const pointMap = new Map<Point, Vote>();

        for (const option of this.pp.votingOptions) {
            pointMap.set(Base8.mulScalar(option), option);
        }

        return pointMap;
    }
}