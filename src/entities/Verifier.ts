import {PublicParameters} from "../models/types";
import {Ballot, BallotConverter, verifyBallot} from "../models/ballot";
import {CasterData} from "./Caster";
import assert from "assert";

export class Verifier {
    casters: Map<number, CasterData>;
    pp: PublicParameters;
    ballots: Map<number, Array<Ballot>>;

    logger: any;

    constructor(casters: Map<number, CasterData>, pp: PublicParameters, logger?: any) {
        this.casters = casters;
        this.pp = pp;
        this.ballots = new Map<number, Array<Ballot>>();
        this.logger = logger;
    }

    async receiveBallot(ballot: Ballot): Promise<void> {
        this.logger?.verbose(`Receiving ballot ${BallotConverter.toShortString(ballot)}`);
        await this.verifyBallotValidity(ballot);

        if (!this.ballots.has(ballot.caster)) {
            this.ballots.set(ballot.caster, new Array<Ballot>());
        }
        this.ballots.get(ballot.caster)!.push(ballot);
    }

    async verifyBallotValidity(ballot: Ballot): Promise<void> {
        this.logger?.verbose(`Verifying ballot ${BallotConverter.toShortString(ballot)}`);
        const data = this.casters.get(ballot.caster);
        assert(data != undefined, "Invalid Caster ID");

        const ballots = this.ballots.get(ballot.caster);

        await verifyBallot(ballot, data, ballots, this.pp);
        this.logger?.verbose(`Ballot OK`);
    }
}