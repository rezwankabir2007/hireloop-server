import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { ObjectId } from 'mongodb';
import bcrypt from 'bcryptjs';
import { createApp } from './app.js';
import { createAccessToken, verifyAccessToken } from './auth.js';

const jwtSecret = 'a-test-secret-that-is-at-least-thirty-two-bytes';

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && !(value instanceof ObjectId)
    && !(value instanceof Date)
    && !(value instanceof RegExp);
}

function equal(left, right) {
  if (left instanceof ObjectId || right instanceof ObjectId) {
    return String(left) === String(right);
  }
  return left === right;
}

function matches(document, query) {
  return Object.entries(query).every(([key, condition]) => {
    if (key === '$or') {
      return condition.some((clause) => matches(document, clause));
    }

    const value = document[key];
    if (isPlainObject(condition)) {
      if ('$in' in condition) {
        return condition.$in.some((candidate) => equal(value, candidate));
      }
      if ('$regex' in condition) {
        return typeof value === 'string'
          && new RegExp(condition.$regex, condition.$options).test(value);
      }
      return false;
    }
    return equal(value, condition);
  });
}

class MemoryCollection {
  constructor(documents = []) {
    this.documents = documents;
  }

  async findOne(query) {
    return this.documents.find((document) => matches(document, query)) || null;
  }

  find(query) {
    return {
      toArray: async () => this.documents.filter((document) => matches(document, query)),
    };
  }

  async insertOne(document) {
    if (document.applicantId && document.jobId
      && this.documents.some((entry) => equal(entry.applicantId, document.applicantId)
        && equal(entry.jobId, document.jobId))) {
      const error = new Error('Duplicate key');
      error.code = 11000;
      throw error;
    }
    const inserted = { ...document, _id: document._id || new ObjectId() };
    this.documents.push(inserted);
    return { acknowledged: true, insertedId: inserted._id };
  }

  async updateOne(query, update) {
    const document = this.documents.find((entry) => matches(entry, query));
    if (!document) {
      return { matchedCount: 0, modifiedCount: 0 };
    }
    Object.assign(document, update.$set);
    return { matchedCount: 1, modifiedCount: 1 };
  }

  async deleteOne(query) {
    const index = this.documents.findIndex((document) => matches(document, query));
    if (index < 0) {
      return { deletedCount: 0 };
    }
    this.documents.splice(index, 1);
    return { deletedCount: 1 };
  }

  async countDocuments(query) {
    return this.documents.filter((document) => matches(document, query)).length;
  }
}

async function createHarness() {
  const password = 'correct-horse-battery';
  const users = new MemoryCollection(await Promise.all(
    ['job_seeker', 'recruiter', 'recruiter', 'admin'].map(async (role, index) => ({
      _id: new ObjectId(),
      email: `user${index}@example.test`,
      passwordHash: await bcrypt.hash(password, 4),
      role,
      premium: false,
    })),
  ));
  const jobs = new MemoryCollection();
  const payments = new MemoryCollection();
  const applications = new MemoryCollection();
  const stripe = { checkout: { sessions: { retrieve: async () => null } } };
  const app = createApp({
    users,
    jobs,
    payments,
    applications,
    stripe,
    jwtSecret,
    imgbbApiKey: 'test-imgbb-key',
  });
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();

  return {
    users,
    jobs,
    applications,
    server,
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

async function withHarness(callback) {
  const harness = await createHarness();
  try {
    await callback(harness);
  } finally {
    await harness.close();
  }
}

function authHeaders(token) {
  return token ? { authorization: `Bearer ${token}` } : {};
}

async function login(harness, index) {
  const response = await fetch(`${harness.url}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: `user${index}@example.test`, password: 'correct-horse-battery' }),
  });
  assert.equal(response.status, 200);
  return (await response.json()).token;
}

async function jsonRequest(harness, path, { method = 'GET', token, body } = {}) {
  const headers = { ...authHeaders(token) };
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
  }
  const response = await fetch(`${harness.url}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { response, body: await response.json() };
}

test('login issues a JWT carrying the database user ID and role', async () => {
  await withHarness(async (harness) => {
    const token = await login(harness, 0);
    const payload = verifyAccessToken(token, jwtSecret);
    assert.equal(payload.sub, harness.users.documents[0]._id.toString());
    assert.equal(payload.role, 'job_seeker');
  });
});

test('valid JWT authenticates a protected user endpoint', async () => {
  await withHarness(async (harness) => {
    const token = await login(harness, 0);
    const { response, body } = await jsonRequest(
      harness,
      `/users/${harness.users.documents[0]._id}/premium`,
      { token },
    );
    assert.equal(response.status, 200);
    assert.equal(body.premium, false);
  });
});

test('protected routes reject missing, malformed, and expired JWTs', async () => {
  await withHarness(async (harness) => {
    const user = harness.users.documents[0];
    const expiredToken = createAccessToken(user, jwtSecret, 1_000_000_000);
    for (const token of [undefined, 'not-a-token', expiredToken]) {
      const { response } = await jsonRequest(
        harness,
        `/users/${user._id}/premium`,
        { token },
      );
      assert.equal(response.status, 401);
    }
  });
});

test('job seekers cannot create jobs', async () => {
  await withHarness(async (harness) => {
    const token = await login(harness, 0);
    const { response } = await jsonRequest(harness, '/jobs', {
      method: 'POST',
      token,
      body: { title: 'Engineer' },
    });
    assert.equal(response.status, 403);
    assert.equal(harness.jobs.documents.length, 0);
  });
});

test('recruiters create jobs with their authenticated MongoDB ID', async () => {
  await withHarness(async (harness) => {
    const token = await login(harness, 1);
    const recruiterId = harness.users.documents[1]._id;
    const otherRecruiterId = harness.users.documents[2]._id;
    const { response, body } = await jsonRequest(harness, '/jobs', {
      method: 'POST',
      token,
      body: { title: 'Engineer', recruiterId: otherRecruiterId.toString() },
    });
    assert.equal(response.status, 201);
    assert.equal(harness.jobs.documents[0].recruiterId.toString(), recruiterId.toString());
    assert.equal(body.insertedId, harness.jobs.documents[0]._id.toString());
  });
});

test('recruiters can see applications for their own jobs only', async () => {
  await withHarness(async (harness) => {
    const recruiterToken = await login(harness, 1);
    const recruiter = harness.users.documents[1];
    const ownJob = { _id: new ObjectId(), recruiterId: recruiter._id };
    const otherJob = { _id: new ObjectId(), recruiterId: harness.users.documents[2]._id };
    harness.jobs.documents.push(ownJob, otherJob);
    harness.applications.documents.push({
      _id: new ObjectId(),
      jobId: ownJob._id,
      applicantId: harness.users.documents[0]._id,
    });

    const own = await jsonRequest(harness, `/jobs/${ownJob._id}/applications`, {
      token: recruiterToken,
    });
    assert.equal(own.response.status, 200);
    assert.equal(own.body.length, 1);

    const other = await jsonRequest(harness, `/jobs/${otherJob._id}/applications`, {
      token: recruiterToken,
    });
    assert.equal(other.response.status, 403);
  });
});

test('job seekers apply as themselves and duplicate applications are rejected', async () => {
  await withHarness(async (harness) => {
    const token = await login(harness, 0);
    const job = { _id: new ObjectId(), recruiterId: harness.users.documents[1]._id };
    harness.jobs.documents.push(job);
    const body = {
      jobId: job._id.toString(),
      applicantId: harness.users.documents[2]._id.toString(),
      coverLetter: 'I am interested',
    };

    const first = await jsonRequest(harness, '/applications', {
      method: 'POST',
      token,
      body,
    });
    assert.equal(first.response.status, 201);
    assert.equal(
      harness.applications.documents[0].applicantId.toString(),
      harness.users.documents[0]._id.toString(),
    );
    assert.equal(harness.applications.documents[0].jobId.toString(), job._id.toString());

    const duplicate = await jsonRequest(harness, '/applications', {
      method: 'POST',
      token,
      body,
    });
    assert.equal(duplicate.response.status, 409);
  });
});

test('admin endpoints allow admins and deny job seekers and recruiters', async () => {
  await withHarness(async (harness) => {
    for (const [index, expectedStatus] of [[3, 200], [0, 403], [1, 403]]) {
      const token = await login(harness, index);
      const { response } = await jsonRequest(harness, '/admin/jobs', { token });
      assert.equal(response.status, expectedStatus);
    }
  });
});

async function uploadProfileImage(harness, token) {
  const originalFetch = globalThis.fetch;
  let imgbbRequestSeen = false;
  globalThis.fetch = async (input, init) => {
    if (String(input).startsWith('https://api.imgbb.com/1/upload')) {
      imgbbRequestSeen = true;
      assert.match(String(input), /key=test-imgbb-key/);
      assert.equal(init.method, 'POST');
      return Response.json({
        success: true,
        data: { url: 'https://i.ibb.co/example/profile.png' },
      });
    }
    return originalFetch(input, init);
  };

  try {
    const form = new FormData();
    form.append(
      'image',
      new Blob([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])], {
        type: 'image/png',
      }),
      'profile.png',
    );
    const response = await fetch(`${harness.url}/users/me/profile-image`, {
      method: 'PUT',
      headers: authHeaders(token),
      body: form,
    });
    return {
      response,
      body: await response.json(),
      imgbbRequestSeen,
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test('profile image upload validates image bytes and returns the ImgBB URL', async () => {
  await withHarness(async (harness) => {
    const token = await login(harness, 0);
    const result = await uploadProfileImage(harness, token);
    assert.equal(result.response.status, 200);
    assert.equal(result.imgbbRequestSeen, true);
    assert.equal(result.body.profileImage, 'https://i.ibb.co/example/profile.png');
  });
});

test('profile image upload persists the URL on the authenticated user', async () => {
  await withHarness(async (harness) => {
    const token = await login(harness, 0);
    const result = await uploadProfileImage(harness, token);
    assert.equal(result.response.status, 200);
    assert.equal(harness.users.documents[0].profileImage, result.body.profileImage);
  });
});
