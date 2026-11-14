import { createHmac, timingSafeEqual } from 'node:crypto';
import { ObjectId } from 'mongodb';

const TOKEN_LIFETIME_SECONDS = 60 * 60;

export class JwtError extends Error {
  constructor(message) {
    super(message);
    this.name = 'JwtError';
  }
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function sign(unsignedToken, secret) {
  return createHmac('sha256', secret).update(unsignedToken).digest('base64url');
}

export function createAccessToken(user, secret, now = Math.floor(Date.now() / 1000)) {
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error('JWT_SECRET must contain at least 32 bytes');
  }

  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = base64UrlEncode(JSON.stringify({
    sub: user._id.toString(),
    role: user.role,
    iat: now,
    exp: now + TOKEN_LIFETIME_SECONDS,
  }));
  const unsignedToken = `${header}.${payload}`;

  return `${unsignedToken}.${sign(unsignedToken, secret)}`;
}

export function verifyAccessToken(token, secret, now = Math.floor(Date.now() / 1000)) {
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error('JWT_SECRET must contain at least 32 bytes');
  }

  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new JwtError('Invalid token');
    }

    const [encodedHeader, encodedPayload, signature] = parts;
    const unsignedToken = `${encodedHeader}.${encodedPayload}`;
    const expectedSignature = Buffer.from(sign(unsignedToken, secret));
    const suppliedSignature = Buffer.from(signature);
    if (expectedSignature.length !== suppliedSignature.length
      || !timingSafeEqual(expectedSignature, suppliedSignature)) {
      throw new JwtError('Invalid token');
    }

    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));

    if (header.alg !== 'HS256'
      || header.typ !== 'JWT'
      || typeof payload.sub !== 'string'
      || !ObjectId.isValid(payload.sub)
      || typeof payload.role !== 'string'
      || !Number.isInteger(payload.iat)
      || !Number.isInteger(payload.exp)
      || payload.iat > now
      || payload.exp <= now
      || payload.exp <= payload.iat
      || payload.exp - payload.iat > TOKEN_LIFETIME_SECONDS) {
      throw new JwtError(payload.exp <= now ? 'Token has expired' : 'Invalid token');
    }

    return payload;
  } catch (error) {
    if (error instanceof JwtError) {
      throw error;
    }
    throw new JwtError('Invalid token');
  }
}

function unauthorized(res, message) {
  return res.status(401).send({ message });
}

export function createAuthenticate(users, secret) {
  return async function authenticate(req, res, next) {
    const authorization = req.get('authorization');
    const match = typeof authorization === 'string'
      ? /^Bearer ([^\s]+)$/i.exec(authorization)
      : null;

    if (!match) {
      return unauthorized(res, 'A Bearer token is required');
    }

    let payload;
    try {
      payload = verifyAccessToken(match[1], secret);
    } catch (error) {
      if (error instanceof JwtError) {
        return unauthorized(res, error.message);
      }
      return next(error);
    }

    try {
      const user = await users.findOne({ _id: new ObjectId(payload.sub) });
      if (!user) {
        return unauthorized(res, 'Invalid or expired token');
      }

      const { passwordHash, ...safeUser } = user;
      req.user = safeUser;
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

export function createRoleVerifier(role) {
  return function verifyRole(req, res, next) {
    if (!req.user) {
      return unauthorized(res, 'Authentication is required');
    }
    if (req.user.role !== role) {
      return res.status(403).send({ message: `Only ${role} users may access this resource` });
    }
    return next();
  };
}

export function createJobOwnershipVerifier(jobs) {
  return async function verifyJobOwnership(req, res, next) {
    if (!req.user || req.user.role !== 'recruiter') {
      return res.status(req.user ? 403 : 401).send({
        message: req.user ? 'Only recruiters may access this resource' : 'Authentication is required',
      });
    }

    const jobId = req.params.id || req.params.jobId || req.body?.jobId || req.query.jobId;
    if (typeof jobId !== 'string' || !ObjectId.isValid(jobId)) {
      return res.status(400).send({ message: 'Invalid job id' });
    }

    try {
      const job = await jobs.findOne({ _id: new ObjectId(jobId) });
      if (!job) {
        return res.status(404).send({ message: 'Job not found' });
      }

      if (!job.recruiterId || job.recruiterId.toString() !== req.user._id.toString()) {
        return res.status(403).send({ message: 'You do not own this job' });
      }

      req.job = job;
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

export const TOKEN_EXPIRES_IN_SECONDS = TOKEN_LIFETIME_SECONDS;
