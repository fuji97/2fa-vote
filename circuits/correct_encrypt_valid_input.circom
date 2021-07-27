include "lib/elgamal.circom"
include "lib/utils.circom"

template CorrectEncryptValidInput(n1, n2, min, max) {
    signal private input m;
    signal private input k;
    signal input P[2];
    signal input B[2];
    signal input Y[2];
    signal output C[2];
    signal output D[2];

    // Calculate M
    component M = Num2Point(n1);
    M.m <== m;
    M.B[0] <== B[0];
    M.B[1] <== B[1];

    // Check input validity - min <= m <= max
    component IsInRangeEnforcer = ForceInRange(n2);
    IsInRangeEnforcer.m <== m;
    IsInRangeEnforcer.min <== min;
    IsInRangeEnforcer.max <== max;

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

component main = CorrectEncryptValidInput(253,8,1,2);