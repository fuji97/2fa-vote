import * as elgamal from "../cryptography/elgamal";
import * as babyjub from "../cryptography/babyjubjub";
import {Scalar} from "../models/types";
import {randomScalar, scalarToPoint} from "../cryptography/babyjubjub";
import {ElGamal} from "../cryptography/elgamal";

const msg = 432432n;

describe("Test ElGamal on Baby JubJub", () => {
    let keypair: babyjub.KeyPair;
    let enc: ElGamal;
    let k: Scalar;

    beforeAll(() => {
        const prv = babyjub.randomScalar();
        k = randomScalar();

        keypair = {
            privateKey: prv,
            publicKey: scalarToPoint(prv)
        };

        enc = elgamal.encrypt(scalarToPoint(msg), keypair.publicKey, k);
    });

    test("Decrypt message", () => {
        const dec = elgamal.decrypt(enc, keypair.privateKey);

        expect(dec.equals(scalarToPoint(msg))).toBeTruthy();
    });

    test("Decrypt with invalid key", () => {
        let prv2 = randomScalar();
        while (prv2 == keypair.privateKey) {
            prv2 = randomScalar();
        }
        const dec = elgamal.decrypt(enc, prv2);

        expect(dec.equals(scalarToPoint(msg))).not.toBeTruthy();
    })
})