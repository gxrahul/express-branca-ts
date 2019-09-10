import BaseError from './BaseError';
class UnauthorizedError extends BaseError {
	public httpStatus: number;
	constructor(code: string, message: string) {
		code = code || 'invalid_token';
		super(code, message);
		this.httpStatus = 401;
	}
}

export default UnauthorizedError;
