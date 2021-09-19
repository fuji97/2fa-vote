import {Point, Scope, Vote} from "../models/types";
import {Authority} from "../entities/Authority";
import * as babyjubjub from "../cryptography/babyjubjub";
import * as lrs from "../cryptography/lrs";
import {Caster, CasterData, EncryptedVote} from "../entities/Caster";
import * as ecdsa from "../cryptography/ecdsa";
import * as eddsa from "../cryptography/eddsa";
import * as elgamal from "../cryptography/elgamal";
import * as proof from "../models/proof";
import {CastedVote, Voter} from "../entities/Voter";
import {Verifier} from "../entities/Verifier";
import {randomScalar} from "../cryptography/babyjubjub";
import {toJson} from "../utils";
import {cesv, cevi} from "../models/proof";
import {Ballot, BallotConverter} from "../models/ballot";

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
    let encryptedVotes: EncryptedVote[];
    let ballots: Ballot[];

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
        encryptedVotes = new Array<EncryptedVote>();
        ballots = new Array<Ballot>();
   });

    it("[Voter] Create and sign initial vote", () => {
        castedVotes[0] = voters[0].castVote(votingOptions[0]);
        castedVotes[1] = voters[1].castVote(votingOptions[1]);
        castedVotes[2] = voters[2].castVote(votingOptions[0]);

        // Check correct vote and sign
        expect(castedVotes[0].vote).toEqual(1n);
        expect(eddsa.verify(castedVotes[0].vote, castedVotes[0].pubKey, castedVotes[0].sign)).toBeTruthy();
        expect(castedVotes[1].vote).toEqual(2n);
        expect(eddsa.verify(castedVotes[1].vote, castedVotes[1].pubKey, castedVotes[1].sign)).toBeTruthy();
        expect(castedVotes[2].vote).toEqual(1n);
        expect(eddsa.verify(castedVotes[2].vote, castedVotes[2].pubKey, castedVotes[2].sign)).toBeTruthy();
   });

    it("[Caster] Verify and encrypt initial vote", async () => {
        const ks = [randomScalar(), randomScalar(), randomScalar()];

        encryptedVotes[0] = await casters[0].encryptVote(castedVotes[0].vote, castedVotes[0].pubKey, castedVotes[0].sign, ks[0]);
        encryptedVotes[1] = await casters[0].encryptVote(castedVotes[1].vote, castedVotes[1].pubKey, castedVotes[1].sign, ks[1]);
        encryptedVotes[2] = await casters[1].encryptVote(castedVotes[2].vote, castedVotes[2].pubKey, castedVotes[2].sign, ks[2]);

        expect(toJson(encryptedVotes[0].vote)).toEqual(toJson(elgamal.encrypt(voteMapping.get(castedVotes[0].vote)!, authority.pp.authorityKey, ks[0])));
        expect(toJson(encryptedVotes[1].vote)).toEqual(toJson(elgamal.encrypt(voteMapping.get(castedVotes[1].vote)!, authority.pp.authorityKey, ks[1])));
        expect(toJson(encryptedVotes[2].vote)).toEqual(toJson(elgamal.encrypt(voteMapping.get(castedVotes[2].vote)!, authority.pp.authorityKey, ks[2])));

        const cesvSignals = [
            await cesv.buildPublicInput(encryptedVotes[0].vote, authority.pp, castedVotes[0].pubKey),
            await cesv.buildPublicInput(encryptedVotes[1].vote, authority.pp, castedVotes[1].pubKey),
            await cesv.buildPublicInput(encryptedVotes[2].vote, authority.pp, castedVotes[2].pubKey)
        ];
        const ceviSignals = [
            await cevi.buildPublicInput(encryptedVotes[0].vote, authority.pp),
            await cevi.buildPublicInput(encryptedVotes[1].vote, authority.pp),
            await cevi.buildPublicInput(encryptedVotes[2].vote, authority.pp)
        ];

        await expect(proof.cesv.verifyProof(encryptedVotes[0].cesv.proof, cesv.toArray(cesvSignals[0]))).resolves.toBeTruthy();
        await expect(proof.cesv.verifyProof(encryptedVotes[1].cesv.proof, cesv.toArray(cesvSignals[1]))).resolves.toBeTruthy();
        await expect(proof.cesv.verifyProof(encryptedVotes[2].cesv.proof, cesv.toArray(cesvSignals[2]))).resolves.toBeTruthy();

        await expect(proof.cevi.verifyProof(encryptedVotes[0].cevi.proof, cevi.toArray(ceviSignals[0]))).resolves.toBeTruthy();
        await expect(proof.cevi.verifyProof(encryptedVotes[1].cevi.proof, cevi.toArray(ceviSignals[1]))).resolves.toBeTruthy();
        await expect(proof.cevi.verifyProof(encryptedVotes[2].cevi.proof, cevi.toArray(ceviSignals[2]))).resolves.toBeTruthy();
    }, 50000);

    it("[Voter] Check validity of encrypted vote", async () => {
        await expect(voters[0].checkEncryptedBallot(encryptedVotes[0])).resolves.toBeUndefined();
        await expect(voters[1].checkEncryptedBallot(encryptedVotes[1])).resolves.toBeUndefined();
        await expect(voters[2].checkEncryptedBallot(encryptedVotes[2])).resolves.toBeUndefined();
    });

    it("[Voter] Apply Linkable Ring Signature to the encrypted vote", () => {
        ballots[0] = voters[0].signBallot(BallotConverter.fromEncryptedVote(encryptedVotes[0]));
        ballots[1] = voters[1].signBallot(BallotConverter.fromEncryptedVote(encryptedVotes[1]));
        ballots[2] = voters[2].signBallot(BallotConverter.fromEncryptedVote(encryptedVotes[2]));

        expect(lrs.verify(BallotConverter.voteToHexString(ballots[0]), ballots[0].voterSign!, voters[0].scope)).toBeTruthy();
        expect(lrs.verify(BallotConverter.voteToHexString(ballots[1]), ballots[1].voterSign!, voters[1].scope)).toBeTruthy();
        expect(lrs.verify(BallotConverter.voteToHexString(ballots[2]), ballots[2].voterSign!, voters[2].scope)).toBeTruthy();

        expect(lrs.link(ballots[0].voterSign!, ballots[1].voterSign!)).not.toBeTruthy();
        expect(lrs.link(ballots[1].voterSign!, ballots[2].voterSign!)).not.toBeTruthy();
        expect(lrs.link(ballots[2].voterSign!, ballots[0].voterSign!)).not.toBeTruthy();
    });

    it("[Caster] Verify Linkable Ring Signature", async () => {
        expect(() => casters[0].verifyVoterSign(ballots[0])).not.toThrow();
        expect(() => casters[0].verifyVoterSign(ballots[1])).not.toThrow();
        expect(() => casters[1].verifyVoterSign(ballots[2])).not.toThrow();
    });

    it("[Caster] Sign ballot and cast", async () => {
        ballots[0] = await casters[0].signBallot(ballots[0]);
        ballots[1] = await casters[0].signBallot(ballots[1]);
        ballots[2] = await casters[1].signBallot(ballots[2]);

        casters[0].castBallot(ballots[0]);
        casters[0].castBallot(ballots[1]);
        casters[1].castBallot(ballots[2]);

        await expect(ecdsa.verify(BallotConverter.voteToHexString(ballots[0]), casters[0].keypair.publicKey, ballots[0].casterSign!)).resolves.toBeTruthy();
        await expect(ecdsa.verify(BallotConverter.voteToHexString(ballots[1]), casters[0].keypair.publicKey, ballots[1].casterSign!)).resolves.toBeTruthy();
        await expect(ecdsa.verify(BallotConverter.voteToHexString(ballots[2]), casters[1].keypair.publicKey, ballots[2].casterSign!)).resolves.toBeTruthy();

        expect(casters[0].signatures).toHaveLength(2);
        expect(casters[1].signatures).toHaveLength(1);
        expect(casters[0].signatures).toEqual([ballots[0].voterSign, ballots[1].voterSign]);
        expect(casters[1].signatures).toEqual([ballots[2].voterSign]);
    });

    it("[Verifier] Receive and verify ballots", async () => {
        for (const verifier of verifiers) {
            for (const ballot of ballots) {
                await expect(verifier.receiveBallot(ballot)).resolves.toBeUndefined();
            }
        }
    });

    it("[Authority] Receive and verify ballots", async () => {
        for (const ballot of ballots) {
            await expect(authority.receiveBallot(ballot)).resolves.toBeUndefined();
        }
    });

    it("[Authority] Tally ballots", () => {
        const expected = {
            "1": 2,
            "2": 1
        };

       const actual = authority.tally();

        expect(Object.fromEntries(actual)).toEqual(expected);
    });
})