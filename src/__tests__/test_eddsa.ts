import * as eddsa from "../cryptography/eddsa";
import {Base8} from "../cryptography/babyjubjub";

const msg = 4857390485n;

describe("Test EdDSA Signature", () => {
    let keypair: eddsa.KeyPair;
    let sig: eddsa.Sign;


    beforeAll(() => {
       keypair = eddsa.generateKeypair();
       sig = eddsa.sign(msg, keypair.privateKey);
    })

    test("Valid signature", () => {
        expect(eddsa.verify(msg, keypair.publicKey, sig)).toBeTruthy();
    });

    test("Bad signature", () => {
        expect(eddsa.verify(msg, keypair.publicKey, { R8: Base8, S: 3123819n })).not.toBeTruthy();
    });

    test("Different message", () => {
        expect(eddsa.verify(12n, keypair.publicKey, sig)).not.toBeTruthy();
    });

    test("Different public key", () => {
        let pk = eddsa.generateKeypair().publicKey;

        while (pk.equals(keypair.publicKey)) {
            pk = eddsa.generateKeypair().publicKey;
        }

        expect(eddsa.verify(msg, pk, sig)).not.toBeTruthy();
    });
});

