#!/bin/sh -e

CESV_PATH="./circuits/correct_encrypt_signed_vote.circom"
CEVI_PATH="./circuits/correct_encrypt_valid_input.circom"
PTAU_CESV="./ptau/powersOfTau28_hez_final_14.ptau"
PTAU_CEVI="./ptau/powersOfTau28_hez_final_14.ptau"
CESV_OUT="./out/correct_encrypt_signed_vote"
CEVI_OUT="./out/correct_encrypt_valid_input"

# circuit_name ptau out_dir
compile_circuit() {
  echo ""
  echo "Compiling the circuit..."
  circom "$1" -r "$3/circuit.r1cs" -w "$3/circuit.wasm"
  echo "Circuit compiled!"
  snarkjs r1cs info "$3/circuit.r1cs"
  echo ""

  input=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 24 ; echo '')
  echo "Creating keys..."
  snarkjs zkey new "$3/circuit.r1cs" "$2" "$3/circuit_0000.zkey"
  echo "Using entropy $input"
  snarkjs zkey contribute "$3/circuit_0000.zkey" "$3/circuit.zkey" -e="$input"
  snarkjs zkey export verificationkey "$3/circuit.zkey" "$3/verification_key.json"
  echo ""
  echo "Keys created!"
}

echo "This script will compile the correct_encrypt_signed_vote and correct_encrypt_valid_input circuits and generate
the corresponding keys from the Power of Tao ceremony specified."
echo ""

mkdir -p $CESV_OUT
mkdir -p $CEVI_OUT

echo "-- Compile circuit $CESV_PATH --"
compile_circuit $CESV_PATH $PTAU_CESV $CESV_OUT

echo ""

echo "-- Compile circuit $CEVI_PATH --"
compile_circuit $CEVI_PATH $PTAU_CEVI $CEVI_OUT

echo ""
echo "+++ DONE! +++"