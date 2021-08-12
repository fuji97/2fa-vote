## Installation
1. Install [NodeJS](https://nodejs.org/it/) (at least v16) and [NPM](https://www.npmjs.com/)
2. Clone the repo and its submodules
```shell
git clone --recurse-submodules --remote-submodules https://github.com/fuji97/2fa-vote.git
```

## Usage
1. Install all dependencies via NPM and build
```shell
npm install
npm run build
```

2. Generate zk-SNARKS initial files
```shell
npm run generate-snarkjs
```
This will run the shell script `snarkjs_generate.sh` that will generate all the files required by snarkjs to works.

Insert random text as Entropy when required (two times).

3. Run tests
```shell
npm test
```
This will run all the unit tests in the project, including the integration test simulating the entire flow of the system.

2. Run default flow
```shell
npm run flow
```
This will simulate a standard flow with vote generation, encryption, proofs verification and tallying. 
Console logs will show all the steps performed with corresponding outputs.
