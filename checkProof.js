const snarkjs = require("snarkjs");
const fs = require("fs");

const inputs = JSON.parse(fs.readFileSync("inputs/inputs.json"));

async function run() {
  console.log("Stating the proof generation");
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    "circuit_js/circuit.wasm",
    "circuit_final.zkey"
  );

  const vKey = JSON.parse(fs.readFileSync("verification_key.json"));

  const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);

  if (res === true) {
    console.log("Verification OK");
  } else {
    console.log("Invalid proof");
  }
}

run().then(() => {
  process.exit(0);
});
