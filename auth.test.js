import test from 'node:test';
import assert from 'node:assert/strict';
import { ObjectId } from 'mongodb';
import {
  createAccessToken,
  createAuthenticate,
  createJobOwnershipVerifier,
  createRoleVerifier,
  verifyAccessToken,
} from './auth.js';

const secret = 'a-test-secret-that-is-at-least-thirty-two-bytes';

function makeResponse() {
  return {
    statusCode: 200,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    send(body) {
      this.body = body;
      return this;
    },
  };
}

test('access tokens contain the user ID and role and expire after one hour', () => {
  const user = { _id: new ObjectId(), role: 'job_seeker' };
  const issuedAt = 1_800_000_000;
  const token = createAccessToken(user, secret, issuedAt);
  const payload = verifyAccessToken(token, secret, issuedAt);

  assert.equal(payload.sub, user._id.toString());
  assert.equal(payload.role, user.role);
  assert.equal(payload.exp, issuedAt + 3600);
});

test('verification rejects invalid signatures and expired tokens', () => {
  const token = createAccessToken(
    { _id: new ObjectId(), role: 'recruiter' },
    secret,
    1_800_000_000,
  );
  assert.throws(() => verifyAccessToken(`${token.slice(0, -1)}x`, secret, 1_800_000_001), {
    message: 'Invalid token',
  });
  assert.throws(() => verifyAccessToken(token, secret, 1_800_003_600), {
    message: 'Token has expired',
  });
});

test('authentication rejects a missing Bearer token', async () => {
  const authenticate = createAuthenticate({ findOne: async () => null }, secret);
  const response = makeResponse();

  await authenticate({ get: () => undefined }, response, () => {
    assert.fail('next should not be called');
  });

  assert.equal(response.statusCode, 401);
  assert.equal(response.body.message, 'A Bearer token is required');
});

test('authentication takes the current role from MongoDB, not the token', async () => {
  const user = { _id: new ObjectId(), role: 'job_seeker', passwordHash: 'secret-hash' };
  const token = createAccessToken({ ...user, role: 'admin' }, secret);
  const authenticate = createAuthenticate({ findOne: async () => user }, secret);
  const request = { get: () => `Bearer ${token}` };
  const response = makeResponse();
  let nextCalled = false;

  await authenticate(request, response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(request.user.role, 'job_seeker');
  assert.equal('passwordHash' in request.user, false);
});

test('role verification rejects a job seeker from recruiter-only routes', () => {
  const response = makeResponse();
  let nextCalled = false;

  createRoleVerifier('recruiter')(
    { user: { role: 'job_seeker' } },
    response,
    () => {
      nextCalled = true;
    },
  );

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 403);
});

test('job ownership accepts only the authenticated recruiter', async () => {
  const recruiterId = new ObjectId();
  const job = { _id: new ObjectId(), recruiterId };
  const verifyOwnership = createJobOwnershipVerifier({
    findOne: async () => job,
  });
  const request = {
    params: { id: job._id.toString() },
    user: { _id: recruiterId, role: 'recruiter' },
  };
  const response = makeResponse();
  let nextCalled = false;

  await verifyOwnership(request, response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(request.job, job);

  const otherResponse = makeResponse();
  await verifyOwnership({
    params: { id: job._id.toString() },
    user: { _id: new ObjectId(), role: 'recruiter' },
  }, otherResponse, () => {
    assert.fail('another recruiter must not be allowed');
  });
  assert.equal(otherResponse.statusCode, 403);
});
