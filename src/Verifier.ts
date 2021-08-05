import * as Buffer from "buffer";
import {PublicParameters, Scope} from "./types";
import {Ballot, BallotConverter} from "./ballot";
import * as proof from "./proof";
import * as ecdsa from "./ecdsa";
import * as lrs from "./lrs";
import {CasterData} from "./Caster";
import assert from "assert";
import {CeviInputConverter} from "./proof";

export class Verifier {
    casters: Map<number, CasterData>;
    pp: PublicParameters;
    ballots: Map<number, Array<Ballot>>;

    constructor(casters: Map<number, CasterData>, pp: PublicParameters) {
        this.casters = casters;
        this.pp = pp;
        this.ballots = new Map<number, Array<Ballot>>();
    }

    receiveBallot(ballot: Ballot): void {

    }

    async checkBallotValidity(ballot: Ballot): Promise<void> {
        const payload = BallotConverter.voteToHexString(ballot);
        const data = this.casters.get(ballot.caster);

        assert(data != undefined, "Invalid Caster ID");

        // Check Caster sign
        await ecdsa.verify(payload, data.publicKey, <ecdsa.Sign>ballot.casterSign);

        // Check Voter Linkable Ring Signature
        lrs.verify(payload, <lrs.LrsSign>ballot.voterSign, data.scope);


        // Check proofs
        const publicSignals = proof.buildCeviPublicInput(ballot.vote, this.pp);
        await proof.verifyCeviProof(ballot.proof, CeviInputConverter.toArray(publicSignals));
    }
}