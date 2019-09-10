import BaseError from "./BaseError";

export class AuthHeaderBadSchemeError extends BaseError {
	static readonly code: string = 'auth_header_bad_scheme';
	static readonly message: string = 'Authorization Scheme should be Bearer';
	constructor() {
		super(AuthHeaderBadSchemeError.code, AuthHeaderBadSchemeError.message);
	}
}

export class AuthHeaderMalformedError extends BaseError {
	static readonly code: string = 'auth_header_bad_format';
	static readonly message: string = 'Format should be Authorization: Bearer <token>';
	constructor() {
		super(AuthHeaderMalformedError.code, AuthHeaderMalformedError.message);
	}
}

export class AuthHeaderMissingError extends BaseError {
	static readonly code: string = 'auth_header_missing';
	static readonly message: string = 'Authorization header is missing';
	constructor() {
		super(AuthHeaderMissingError.code, AuthHeaderMissingError.message);
	}
}
