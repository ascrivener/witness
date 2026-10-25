// Compiles Toys.sol with solcjs (npm `solc@0.8.28`) and writes each contract's runtime code as
// `<Name>.hex`. Run from anywhere with solc installed: `NODE_PATH=... node compile.js`.
const fs = require('fs');
const path = require('path');
const solc = require('solc');
const dir = __dirname;
const input = {
	language: 'Solidity',
	sources: { 'Toys.sol': { content: fs.readFileSync(path.join(dir, 'Toys.sol'), 'utf8') } },
	settings: {
		optimizer: { enabled: true, runs: 200 },
		evmVersion: 'cancun',
		outputSelection: { '*': { '*': ['evm.deployedBytecode.object'] } },
	},
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
for (const e of out.errors || []) {
	console.error(e.formattedMessage);
	if (e.severity === 'error') process.exit(1);
}
for (const [name, c] of Object.entries(out.contracts['Toys.sol'])) {
	fs.writeFileSync(path.join(dir, `${name}.hex`), c.evm.deployedBytecode.object + '\n');
	console.log(name, c.evm.deployedBytecode.object.length / 2, 'bytes');
}
