export default class BaseError extends Error {
	public code: string;
	constructor(code: string, message: string) {
		super(message);
		Object.setPrototypeOf(this, new.target.prototype);
		this.code = code;
		const captureStackTrace: Function = (Error as any).captureStackTrace;
		captureStackTrace && captureStackTrace(this, this.constructor);
	}
}
