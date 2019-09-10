import branca from 'branca';
import expressBranca from '../index';
import UnauthorizedError from '../errors/UnauthorizedError';
import {AuthHeaderBadSchemeError, AuthHeaderMalformedError, AuthHeaderMissingError} from '../errors/AuthHeaderError';
import { Request, Response, NextFunction } from 'express';
import { request } from 'http';

let req: Request;
let res: Response;
let options: any = {};

const setBeforeEach = () => beforeEach(() => {
	req = {} as Request;
	res = {} as Response;
	options = {
		secret: 'supersecretkeyyoushouldnotcommit'
		// authentication is enabled by default
	}
});

describe('Configuration Tests', () => {
	setBeforeEach();
	it('should throw error when secret not set', () => {
		expect(() => expressBranca()).toThrowError('secret is required');
	});

	it('should throw error when secret length is not 32 bytes', () => {
		options.secret = 'secretlongerthan32bytes1234567890';
		expect(() => expressBranca(options)).toThrowError('secret length must be 32 bytes');
	});
});

describe('Authorization Header tests', () => {
	setBeforeEach();
	it('should skip authentication for CORS preflight', () => {
		req.method = 'OPTIONS';
		req.headers = {
			'access-control-request-headers': 'sasa, sras, authorization'
		};
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).toBe(undefined);
		});
	});

	it('should throw error if authentication is required and authorization header is missing', () => {
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect(err.code).toBe('auth_header_missing');
		})
	});

	it('should pass if authentication is not required and authorization header is missing', () => {
		options.isAuthRequired = false;
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).toBeUndefined();
		})
	});

	it('should throw error if authentication is required and authorization header scheme is not Bearer', () => {
		const middleware = expressBranca(options);
		req.headers = {
			'authorization': 'NotBearer sometoken'
		};
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect(err.code).toBe('auth_header_bad_scheme');
		})
	});

	it('should pass if authentication is not required and authorization header scheme is not Bearer', () => {
		options.isAuthRequired = false;
		const middleware = expressBranca(options);
		req.headers = {
			'authorization': 'NotBearer sometoken'
		};
		middleware(req, res, (err) => {
			expect(err).toBeUndefined();
		})
	});

	it('should throw error if authetication is required and authorization header format is malformed', () => {
		const middleware = expressBranca(options);
		req.headers = {
			'authorization': 'malformed'
		};
		middleware(req, res, (err) => {
			expect(err).not.toBe(undefined);
			expect(err.code).toBe('auth_header_bad_format');
		})
	});

	it('should still throw error if authetication is "not required" and authorization header format is malformed', () => {
		options.isAuthRequired = false;
		const middleware = expressBranca(options);
		req.headers = {
			'authorization': 'malformed auth header'
		};
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect(err.code).toBe('auth_header_bad_format');
		})
	});
});

describe('Token validity tests', () => {
	setBeforeEach();
	it('should still decode token if present and valid, even if authentication is disabled', () => {
		options.isAuthRequired = false;
		const payload = {
			"param1": "value1",
			"param2": "value2"
		};
		const jsonPayload: string = JSON.stringify(payload);
		const objBranca = branca(options.secret);
		const token: string = objBranca.encode(jsonPayload);
		const authHeader = `Bearer ${token}`;
		req.headers = {
			authorization: authHeader
		};
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).toBeUndefined();
			expect((req as any).token).toBe(token);
			const dPayload = JSON.parse((req as any).decoded);
			expect(dPayload).toMatchObject(payload);
		});
	});

	it('should throw error if token can not be decoded', () => {
		const token: string = 'randomstring';
		const authHeader = `Bearer ${token}`;
		req.headers = {
			authorization: authHeader
		};
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect(err).toBeInstanceOf(UnauthorizedError);
			expect((err as any).code).toBe('invalid_token');
		});
	});

	it('should throw error if wrong secret is passed', () => {
		const payload = {
			"param1": "value1",
			"param2": "value2"
		};
		const jsonPayload: string = JSON.stringify(payload);
		const objBranca = branca('thisiswrongsecretabcxyz123456789');
		const token: string = objBranca.encode(jsonPayload, 1565686608);
		const authHeader = `Bearer ${token}`;
		req.headers = {
			authorization: authHeader
		};
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect(err).toBeInstanceOf(UnauthorizedError);
			expect((err as any).code).toBe('invalid_token');
		});
	});

	it('should throw error if wrong secret is passed, even if authentication is disabled', () => {
		options.isAuthRequired = false;
		const payload = {
			"param1": "value1",
			"param2": "value2"
		};
		const jsonPayload: string = JSON.stringify(payload);
		const objBranca = branca('thisiswrongsecretabcxyz123456789');
		const token: string = objBranca.encode(jsonPayload);
		const authHeader = `Bearer ${token}`;
		req.headers = {
			authorization: authHeader
		};
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect(err).toBeInstanceOf(UnauthorizedError);
			expect((err as any).code).toBe('invalid_token');
		});
	});

	it('should throw "invalid_token" error if token has expired and authentication is required', () => {
		options.ttl = 10;
		const payload = {
			"param1": "value1",
			"param2": "value2"
		};
		const jsonPayload: string = JSON.stringify(payload);
		const objBranca = branca(options.secret);
		const token: string = objBranca.encode(jsonPayload, 1565686608);
		const authHeader = `Bearer ${token}`;
		req.headers = {
			authorization: authHeader
		};
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect(err).toBeInstanceOf(UnauthorizedError);
			expect((err as any).code).toBe('expired_token');
		});
	});

	it('should still return error if token has expired and authentication is not required', () => {
		options.isAuthRequired = false;
		options.ttl = 10;
		const payload = {
			"param1": "value1",
			"param2": "value2"
		};
		const jsonPayload: string = JSON.stringify(payload);
		const objBranca = branca(options.secret);
		const token: string = objBranca.encode(jsonPayload, 1565686608);
		const authHeader = `Bearer ${token}`;
		req.headers = {
			authorization: authHeader
		};
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect(err).toBeInstanceOf(UnauthorizedError);
			expect((err as any).code).toBe('expired_token');
			expect((req as any).token).toBeUndefined();
			expect((req as any).decoded).toBeUndefined();
		});
	});
});

describe('custom getToken tests', () => {
	setBeforeEach();
	it('should return errors thrown from custom getToken function', () => {
		options.getToken = (req) => {
			throw new Error('missing custom authorization header');
		};
		const middleware = expressBranca(options);
		middleware(req, res, (err) => {
			expect(err).not.toBeUndefined();
			expect((err as any).code).toBe('invalid_token');
			expect((err as any).message).toBe('missing custom authorization header');
		});
	});

	it('should work with custom getToken function', () => {
		options.getToken = (req) => {
			return req.headers.xauthorization;
		};
		const middleware = expressBranca(options);
		const payload = {
			"param1": "value1",
			"param2": "value2"
		};
		const jsonPayload: string = JSON.stringify(payload);
		const objBranca = branca(options.secret);
		const token: string = objBranca.encode(jsonPayload);
		req.headers = {
			'xauthorization': `${token}`
		};
		middleware(req, res, (err) => {
			expect(err).toBeUndefined();
			expect((req as any).token).toBe(token);
			const decodedToken = JSON.parse((req as any).decoded);
			expect(decodedToken).toMatchObject(payload);
		});
	});
});
