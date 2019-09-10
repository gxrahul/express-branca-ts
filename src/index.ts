import UnauthorizedError from './errors/UnauthorizedError';
import {AuthHeaderBadSchemeError, AuthHeaderMalformedError, AuthHeaderMissingError} from './errors/AuthHeaderError';
import branca from 'branca';
import { Request, Response, NextFunction } from 'express';
import { Interface } from 'readline';

const getToken = (req: Request): string => {
	if(req && req.headers && req.headers.authorization) {
		const authHeaderParts = req.headers.authorization.split(' ');
		const [scheme = '', token = ''] = authHeaderParts;
		if(authHeaderParts.length === 2 && scheme && token) {
			//@TODO: test which one is faster
			// if(/^Bearer$/.test(scheme)) {
			if(scheme.toLowerCase() === 'bearer') {
				return token;
			} else {
				throw new AuthHeaderBadSchemeError();
			}
		} else {
			throw new AuthHeaderMalformedError();
		}
	}
	throw new AuthHeaderMissingError();
}

const defaultOptions = {
	secret: '',
	isAuthRequired: true,
	getToken: getToken,
	ttl: undefined
};

export default (_options = {}) => {
	const options = {...defaultOptions, ..._options};
	if(!options.secret) {
		throw new Error('secret is required');
	}
	if(options.secret.length !== 32) {
		throw new Error('secret length must be 32 bytes');
	}
	const objBranca = branca(options.secret);
	const middleware = (req: Request, res: Response, next: NextFunction) => {
		let token: string = '';
		let decodedToken: string = '';
		// handle CORS preflight
		if(req.method === 'OPTIONS' && Object.prototype.hasOwnProperty.call(req.headers, 'access-control-request-headers')) {
			const corsHeaders: string = req.headers['access-control-request-headers'] as string;
			const allowedHeaders: string[] = corsHeaders.split(',').map((header) => header.trim().toLowerCase());
			if(allowedHeaders.includes('authorization')) {
				return next();
			}
		}
		try {
			token = options.getToken(req);
		} catch(ex) {
			// return error if header is malformed
			// otherwise return an error, when auth is required
			if(ex instanceof AuthHeaderMalformedError || options.isAuthRequired) {
				return next(new UnauthorizedError(ex.code, ex.message));
			}
		}
		try {
			if(token) {
				decodedToken = objBranca.decode(token, options.ttl);
			}
		} catch(ex) {
			// return error, if token is not valid
			switch(ex.message) {
				case 'Invalid token version.':
					return next(new UnauthorizedError('invalid_token_version', ex.message));
				case 'Token is expired.':
					return next(new UnauthorizedError('expired_token', ex.message));
				default:
					return next(new UnauthorizedError('invalid_token', 'Failed to decode, token is invalid'));
			}
		}
		if(options.isAuthRequired && (!token || !decodedToken)) {
			return next(new UnauthorizedError('invalid_token', 'Token is not valid'));
		}
		if(token && decodedToken) {
			(req as any).token = token;
			(req as any).decoded = decodedToken;
		}
		next();
	};
	return middleware;
};
