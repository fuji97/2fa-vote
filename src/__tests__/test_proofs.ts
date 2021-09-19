import {cesv, CesvInput, CesvPublicInput, cevi, CeviInput, CeviPublicInput} from "../models/proof";
import * as eddsa from "../cryptography/eddsa";
import * as babyjub from "../cryptography/babyjubjub";
import * as elgamal from "../cryptography/elgamal";
import {PublicParameters, Scalar} from "../models/types";
import {randomScalar, scalarToPoint} from "../cryptography/babyjubjub";
import {EncryptedVote} from "../entities/Caster";
import {toJson} from "../utils";

const vote = 1n;

describe("Test Zero Knowledge Proofs", () => {
    let pp: PublicParameters;
    let authorityKeypair: babyjub.KeyPair;
    let voterKeypair: eddsa.KeyPair;
    let ballot: EncryptedVote;
    let k: Scalar;

    beforeAll(async () => {
        const authorityPrv = randomScalar();
        authorityKeypair = {
            privateKey: authorityPrv,
            publicKey: scalarToPoint(authorityPrv)
        };

        pp = {
            authorityKey: authorityKeypair.publicKey,
            elGamalBasePoint: babyjub.Base8,
            elGamalPPoint: babyjub.Base8,
            votingOptions: [1n, 2n]
        };

        voterKeypair = eddsa.generateKeypair();

        const sig = eddsa.sign(vote, voterKeypair.privateKey);
        k = randomScalar();

        const cesvInput: CesvInput = {
            B: babyjub.Base8.toArray(),
            P: babyjub.Base8.toArray(),
            R8: sig.R8.toArray(),
            Y: pp.authorityKey.toArray(),
            k: k,
            m: vote,
            pub: voterKeypair.publicKey.toArray(),
            s: sig.S

        }
        const cesvProof = await cesv.generateProof(cesvInput);

        const ceviInput: CeviInput = {
            B: babyjub.Base8.toArray(),
            P: babyjub.Base8.toArray(),
            Y: pp.authorityKey.toArray(),
            k: k,
            m: vote
        }
        const ceviProof = await cevi.generateProof(ceviInput);

        ballot = {
            caster: 0,
            cesv: cesvProof,
            cevi: ceviProof,
            vote: cesv.extractVote(cesv.fromArray(cesvProof.publicSignals))
        };
    }, 30000);

    test("Compare encrypted votes", () => {
        const cesvVote = cesv.extractVote(cesv.fromArray(ballot.cesv.publicSignals));
        const ceviVote = cevi.extractVote(cevi.fromArray(ballot.cevi.publicSignals));

        expect(toJson(ceviVote)).toEqual(toJson(cesvVote));
    });

    test("Verify generated inputs", () => {
        const cesvInput = cesv.buildPublicInput(ballot.vote, pp, voterKeypair.publicKey);
        const ceviInput = cevi.buildPublicInput(ballot.vote, pp);

        expect(toJson(cesv.fromArray(ballot.cesv.publicSignals))).toEqual(toJson(cesvInput));
        expect(toJson(cevi.fromArray(ballot.cevi.publicSignals))).toEqual(toJson(ceviInput));
    });

    test("Verify ElGamal encryption", async () => {
        const enc = elgamal.encrypt(scalarToPoint(vote), authorityKeypair.publicKey, k);

        expect(toJson(ballot.vote)).toEqual(toJson(enc));
    });

    test("Verify CESV", async () => {
        await expect(cesv.verifyProof(ballot.cesv.proof, ballot.cesv.publicSignals)).resolves.toBeTruthy();
    });

    test("Verify CEVI", async () => {
        await expect(cevi.verifyProof(ballot.cevi.proof, ballot.cevi.publicSignals)).resolves.toBeTruthy();
    });

    test("Generate CEVI proof with an invalid vote", async () => {
        const ceviInput: CeviInput = {
            B: babyjub.Base8.toArray(),
            P: babyjub.Base8.toArray(),
            Y: pp.authorityKey.toArray(),
            k: k,
            m: 4n
        };
        const proof = await cevi.generateProof(ceviInput);

        await expect(cevi.verifyProof(proof.proof, proof.publicSignals)).resolves.not.toBeTruthy();
    });

    test("Generate CESV proof with an invalid signature", async () => {
        const sig2 = eddsa.sign(2n, voterKeypair.privateKey);

        const cesvInput: CesvInput = {
            B: babyjub.Base8.toArray(),
            P: babyjub.Base8.toArray(),
            R8: sig2.R8.toArray(),
            Y: pp.authorityKey.toArray(),
            k: k,
            m: vote,
            pub: voterKeypair.publicKey.toArray(),
            s: sig2.S

        }
        const proof = await cesv.generateProof(cesvInput);

        await expect(cesv.verifyProof(proof.proof, proof.publicSignals)).resolves.not.toBeTruthy();
    });

    test("Generate CESV proof with an invalid public key", async () => {
        const sig = eddsa.sign(vote, voterKeypair.privateKey);
        const pub = eddsa.generateKeypair();

        const cesvInput: CesvInput = {
            B: babyjub.Base8.toArray(),
            P: babyjub.Base8.toArray(),
            R8: sig.R8.toArray(),
            Y: pp.authorityKey.toArray(),
            k: k,
            m: vote,
            pub: pub.publicKey.toArray(),
            s: sig.S

        }
        const proof = await cesv.generateProof(cesvInput);

        await expect(cesv.verifyProof(proof.proof, proof.publicSignals)).resolves.not.toBeTruthy();
    });

    test("Verify CEVI proof with an invalid authority key", async () => {
        let newPrivKey = randomScalar();
        while (newPrivKey == pp.authorityKey) {
            newPrivKey = randomScalar();
        }

        const ceviPublicInput: CeviPublicInput = {
            C: ballot.vote.C.toArray(),
            D: ballot.vote.D.toArray(),
            B: babyjub.Base8.toArray(),
            P: babyjub.Base8.toArray(),
            Y: scalarToPoint(newPrivKey).toArray()
        };

        await expect(cevi.verifyProof(ballot.cevi.proof, cevi.toArray(ceviPublicInput))).resolves.not.toBeTruthy();
    });

    test("Verify CESV proof with an invalid Voter public key", async () => {
        let newKeypair = eddsa.generateKeypair();
        while (newKeypair.privateKey == voterKeypair.privateKey) {
            newKeypair = eddsa.generateKeypair();
        }

        const cesvPublicInput: CesvPublicInput = {
            pub: newKeypair.publicKey.toArray(),
            C: ballot.vote.C.toArray(),
            D: ballot.vote.D.toArray(),
            B: babyjub.Base8.toArray(),
            P: babyjub.Base8.toArray(),
            Y: pp.authorityKey.toArray()
        };

        await expect(cesv.verifyProof(ballot.cesv.proof, cesv.toArray(cesvPublicInput))).resolves.not.toBeTruthy();
    });
});