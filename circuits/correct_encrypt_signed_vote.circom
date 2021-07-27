include "../circomlib/circuits/eddsamimc.circom";
include "lib/elgamal.circom";
include "lib/utils.circom";

template CorrectEncryptSignedVote(n) {
    signal private input m;
    signal private input k;
    signal input P[2];
    signal input B[2];
    signal input Y[2];
    signal private input s;
    signal private input R8[2];
    signal input pub[2];
    signal output C[2];
    signal output D[2];

    // Calculate M
    component M = Num2Point(n);
    M.m <== m;
    M.B[0] <== B[0];
    M.B[1] <== B[1];

    // Verify EdDSA MiMC
    component verifyEddsa = EdDSAMiMCVerifier();
    verifyEddsa.enabled <== 1;
    verifyEddsa.Ax <== pub[0];
    verifyEddsa.Ay <== pub[1];
    verifyEddsa.S <== s;
    verifyEddsa.R8x <== R8[0];
    verifyEddsa.R8y <== R8[1];
    verifyEddsa.M <== m;

    // Generate ElGamal Encryption
    component ElGamal = ElGamalEncrypt();
    ElGamal.M[0] <== M.P[0];
    ElGamal.M[1] <== M.P[1];
    ElGamal.k <== k;
    ElGamal.P[0] <== P[0];
    ElGamal.P[1] <== P[1];
    ElGamal.Y[0] <== Y[0];
    ElGamal.Y[1] <== Y[1];
    C[0] <== ElGamal.C[0];
    C[1] <== ElGamal.C[1];
    D[0] <== ElGamal.D[0];
    D[1] <== ElGamal.D[1];
}

component main = CorrectEncryptSignedVote(253);