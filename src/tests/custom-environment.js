const NodeEnvironment = require('jest-environment-node');

class CustomEnvironment extends NodeEnvironment {
	constructor(config) {
		super({...config, ...{
			globals: {
				Uint8Array: Uint8Array,
				ArrayBuffer: ArrayBuffer
			}
		}});
	}
}

module.exports = CustomEnvironment;
