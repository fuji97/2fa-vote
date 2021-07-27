include "../../circomlib/circuits/escalarmulany.circom";
include "../../circomlib/circuits/bitify.circom";
include "../../circomlib/circuits/comparators.circom";

template Num2Point(n) {
    signal input m;
    signal input B[2];
    signal output P[2];

    component mBits = Num2Bits(n);
    mBits.in <== m;
    component M = EscalarMulAny(n);
    M.p[0] <== B[0];
    M.p[1] <== B[1];
    for (var i = 0; i < 253; i ++) {
        M.e[i] <== mBits.out[i];
    }

    P[0] <== M.out[0];
    P[1] <== M.out[1];
}

template ForceInRange(n) {
    signal input m;
    signal input min;
    signal input max;

    component MinComparator = GreaterEqThan(n);
    MinComparator.in[0] <== m;
    MinComparator.in[1] <== min;
    MinComparator.out === 1;
    component MaxComparator = LessEqThan(n);
    MaxComparator.in[0] <== m;
    MaxComparator.in[1] <== max;
    MaxComparator.out === 1;
}