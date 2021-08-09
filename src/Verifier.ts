import {PublicParameters} from "./types";
import {Ballot, verifyBallot} from "./ballot";
import {CasterData} from "./Caster";
import assert from "assert";

export class Verifier {
    casters: Map<number, CasterData>;
    pp: PublicParameters;
    ballots: Map<number, Array<Ballot>>;

    constructor(casters: Map<number, CasterData>, pp: PublicParameters) {
        this.casters = casters;
        this.pp = pp;
        this.ballots = new Map<number, Array<Ballot>>();
    }

    async receiveBallot(ballot: Ballot): Promise<void> {
        await this.verifyBallotValidity(ballot);

        if (!this.ballots.has(ballot.caster)) {
            this.ballots.set(ballot.caster, new Array<Ballot>());
        }
        this.ballots.get(ballot.caster)!.push(ballot);
    }

    async verifyBallotValidity(ballot: Ballot): Promise<void> {
        const data = this.casters.get(ballot.caster);
        assert(data != undefined, "Invalid Caster ID");

        const ballots = this.ballots.get(ballot.caster);

        await verifyBallot(ballot, data, ballots, this.pp);
    }
}