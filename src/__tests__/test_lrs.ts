import * as lrs from "../lrs";
import {Scope} from "../types";

const msg = "Hello World!";

describe("Test Linkable Ring Signature", () => {
    let keypairs: lrs.KeyPair[];
    let scope: Scope;
    let sig: lrs.Sign;

    beforeAll(() => {
        keypairs = [
            lrs.generateKeypair(),
            lrs.generateKeypair(),
            lrs.generateKeypair(),
            lrs.generateKeypair()
        ];

        scope = keypairs.map(x => x.publicKey);

        sig = lrs.sign(msg, keypairs[0], scope);
    });

    test("Verify signature", () => {
        expect(lrs.verify(msg, sig, scope)).toBeTruthy();
    });

    test("Invalid signature", () => {
        const sig2 = lrs.sign("Another message", keypairs[1], scope);

        expect(lrs.verify(msg, sig2, scope)).not.toBeTruthy();
    });

    test("Different message", () => {
        expect(lrs.verify("Different message", sig, scope)).not.toBeTruthy();
    });

    test("Different scope", () => {
        const scope2 = [ lrs.generateKeypair(), lrs.generateKeypair() ].map(x => x.publicKey);

        expect(lrs.verify(msg, sig, scope2)).not.toBeTruthy();
    });

    test("Linkability from different signer", () => {
        const sig2 = lrs.sign("Second message", keypairs[1], scope);
        const sig3 = lrs.sign("Third message", keypairs[2], scope);

        expect(lrs.link(sig, sig2)).not.toBeTruthy();
        expect(lrs.link(sig, sig3)).not.toBeTruthy();
        expect(lrs.link(sig2, sig3)).not.toBeTruthy();
    });

    test("Linkability from the same signer", () => {
        const sig2 = lrs.sign("Second message", keypairs[0], scope);
        const sig3 = lrs.sign("Third message", keypairs[0], scope);

        expect(lrs.link(sig, sig2)).toBeTruthy();
        expect(lrs.link(sig, sig3)).toBeTruthy();
        expect(lrs.link(sig2, sig3)).toBeTruthy();
        expect(lrs.link(sig, sig)).toBeTruthy();
    })
});