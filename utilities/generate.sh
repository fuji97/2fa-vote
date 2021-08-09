#!/bin/sh -e
# Circuit Input Ptau

echo "Compiling the circuit..."
circom $1 -r artifacts/circuit.r1cs -w artifacts/circuit.wasm -s artifacts/circuit.sym
echo "Circuit compiled!"
snarkjs r1cs info artifacts/circuit.r1cs
echo "\n"

echo "Creating keys..."
snarkjs zkey new artifacts/circuit.r1cs $3 keys/circuit_0000.zkey
snarkjs zkey contribute keys/circuit_0000.zkey keys/circuit_final.zkey
snarkjs zkey export verificationkey keys/circuit_final.zkey out/verification_key.json
echo "\n"

echo "Generating the witness..."
snarkjs wtns calculate artifacts/circuit.wasm $2 artifacts/witness.wtns
snarkjs wtns debug artifacts/circuit.wasm $2 artifacts/witness.wtns artifacts/circuit.sym
snarkjs wtns export json artifacts/witness.wtns artifacts/witness.json
echo "\n"

echo "Generating the proof..."
snarkjs groth16 prove keys/circuit_final.zkey artifacts/witness.wtns out/proof.json out/public.json
echo "\n"

echo "Verifying the proof..."
snarkjs groth16 verify out/verification_key.json out/public.json out/proof.json
echo "\n"

echo "+++ DONE! +++"