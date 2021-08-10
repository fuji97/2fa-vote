import {Point, Scope, Vote} from "../types";
import {Authority} from "../Authority";
import * as babyjubjub from "../babyjubjub";
import * as lrs from "../lrs";
import {Caster, CasterData} from "../Caster";
import * as ecdsa from "../ecdsa";
import * as eddsa from "../eddsa";
import {CastedVote, Voter} from "../Voter";
import {Verifier} from "../Verifier";

describe("Test protocol flow", () => {
    const votingOptions: Vote[] = [1n, 2n];
    const voteMapping: Map<Vote, Point> = new Map<Vote, Point>([
        [1n, babyjubjub.scalarToPoint(1n)],
        [2n, babyjubjub.scalarToPoint(2n)]
    ]);
    let scopes: Scope[];
    let authority: Authority;
    let casters: Caster[];
    let voters: Voter[];
    let verifiers: Verifier[];

    let castedVotes: CastedVote[];

    it("Create data and entities", () => {
        authority = new Authority(babyjubjub.generateKeypair(), votingOptions);

        const scopesKeys = [[
            lrs.generateKeypair(),
            lrs.generateKeypair(),
            lrs.generateKeypair()
        ],[
            lrs.generateKeypair(),
            lrs.generateKeypair(),
            lrs.generateKeypair()]
        ];
        scopes = [
            scopesKeys[0].map(x => x.publicKey),
            scopesKeys[1].map(x => x.publicKey)
        ];

        casters = [
            new Caster(0, ecdsa.generateKeypair(), scopes[0], authority.pp),
            new Caster(1, ecdsa.generateKeypair(), scopes[1], authority.pp)
        ];

        const castersData = new Map<number, CasterData>([
            [casters[0].id, { publicKey: casters[0].keypair.publicKey, scope: scopes[0] }],
            [casters[1].id, { publicKey: casters[1].keypair.publicKey, scope: scopes[1] }]
        ]);

        voters = [
            new Voter(scopesKeys[0][0], scopes[0], casters[0].keypair.publicKey, authority.pp),
            new Voter(scopesKeys[0][1], scopes[0], casters[0].keypair.publicKey, authority.pp),
            new Voter(scopesKeys[1][0], scopes[1], casters[1].keypair.publicKey, authority.pp),
        ];

        verifiers = [
            new Verifier(castersData, authority.pp),
            new Verifier(castersData, authority.pp)
        ];

        // Add scope in authority
        authority.casters = castersData;

        // Initialize future fields
        castedVotes = new Array<CastedVote>();
   });

    it("Create and sign initial vote", () => {
        castedVotes[0] = voters[0].castVote(votingOptions[0]);
        castedVotes[1] = voters[1].castVote(votingOptions[1]);
        castedVotes[2] = voters[2].castVote(votingOptions[0]);

        // Check correct vote and sign
        expect(castedVotes[0].vote).toEqual(1n);
        expect(eddsa.verify(castedVotes[0].vote, castedVotes[0].pubKey, castedVotes[0].sign));
        expect(castedVotes[1].vote).toEqual(2n);
        expect(eddsa.verify(castedVotes[1].vote, castedVotes[1].pubKey, castedVotes[1].sign));
        expect(castedVotes[2].vote).toEqual(1n);
        expect(eddsa.verify(castedVotes[2].vote, castedVotes[2].pubKey, castedVotes[2].sign));
   });
});