include "../../circomlib/circuits/escalarmulany.circom";
include "../../circomlib/circuits/pointbits.circom";
include "../../circomlib/circuits/bitify.circom";
include "../../circomlib/circuits/babyjub.circom";

template ElGamalEncrypt() {
    signal input M[2];
    signal input k;
    signal input P[2];
    signal input Y[2];
    signal output C[2];
    signal output D[2];

    // Convert message to bits
    // component messageBits = Num2Bits(256);
    // messageBits.in <== M;

    // Convert k to bits
    component kBits = Num2Bits(253);
    kBits.in <== k;
    
    // Convert bits to point
    // component messagePoint = Bits2Point_Strict();
    // for (var i = 0; i < 256; i ++) {
    //     messagePoint.in[i] <== messageBits.out[i];
    // }

    // TODO Maybe add P curve check

    // Calculate c1
    // (k * P)
    component cx = EscalarMulAny(253);
    cx.p[0] <== P[0];
    cx.p[1] <== P[1];
    for (var i = 0; i < 253; i ++) {
        cx.e[i] <== kBits.out[i];
    }
    C[0] <== cx.out[0];
    C[1] <== cx.out[1];

    // Calculate c2
    // (k * Y)
    component dx = EscalarMulAny(253);
    dx.p[0] <== Y[0];
    dx.p[1] <== Y[1];
    for (var i = 0; i < 253; i ++) {
        dx.e[i] <== kBits.out[i];
    }

    // (k * Y) + M
    component dadd = BabyAdd();
    dadd.x1 <== dx.out[0];
    dadd.y1 <== dx.out[1];
    dadd.x2 <== M[0];
    dadd.y2 <== M[1];

    D[0] <== dadd.xout;
    D[1] <== dadd.yout;
}

/*
 * FROM: https://github.com/weijiekoh/elgamal-babyjub
 * Decrypts an ElGamal ciphertext.
 * The plaintext is the x-value of the decrypted point minus xIncrement.
 * The comments and signal names follow the symbols used here:
 * https://ethresear.ch/t/maci-anonymization-using-rerandomizable-encryption/7054
 *
 * c1, c2:     The ciphertext
 * xIncrement: Deduct this from the decrypted point's x-value to obtain the
 *             plaintext
 * privKey:    The private key
 * out:        The plaintext
 *
 * m = ((c1 ** x) ** - 1) * c2
 * out = m.x - xIncrement
 */
template ElGamalDecrypt() {
    signal input c1[2];
    signal input c2[2];
    signal private input privKey;
    signal output out[2];

    // Convert the private key to bits
    component privKeyBits = Num2Bits(253);
    privKeyBits.in <== privKey;
    
    // c1 ** x
    component c1x = EscalarMulAny(253);
    for (var i = 0; i < 253; i ++) {
        c1x.e[i] <== privKeyBits.out[i];
    }
    c1x.p[0] <== c1[0];
    c1x.p[1] <== c1[1];

    // (c1 ** x) ** -1
    signal c1xInverseX;
    c1xInverseX <== 0 - c1x.out[0];

    // ((c1 ** x) ** - 1) * c2
    component decryptedPoint = BabyAdd();
    decryptedPoint.x1 <== c1xInverseX;
    decryptedPoint.y1 <== c1x.out[1];
    decryptedPoint.x2 <== c2[0];
    decryptedPoint.y2 <== c2[1];

    out[0] <== decryptedPoint.xout;
    out[1] <== decryptedPoint.yout;
}