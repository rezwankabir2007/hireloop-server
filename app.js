import express from 'express';
import { ObjectId } from 'mongodb';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import {
  createAccessToken,
  createAuthenticate,
  createJobOwnershipVerifier,
  createRoleVerifier,
  TOKEN_EXPIRES_IN_SECONDS,
} from './auth.js';

const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const allowedImageTypes = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);

export function createApp({ users, jobs, payments, applications, stripe, jwtSecret, imgbbApiKey }) {
  if (!jwtSecret || Buffer.byteLength(jwtSecret) < 32) {
    throw new Error('JWT_SECRET must be set to a secret of at least 32 bytes');
  }

  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(cors());

  const authenticate = createAuthenticate(users, jwtSecret);
  const verifyJobSeeker = createRoleVerifier('job_seeker');
  const verifyRecruiter = createRoleVerifier('recruiter');
  const verifyAdmin = createRoleVerifier('admin');
  const verifyRecruiterJobOwnership = createJobOwnershipVerifier(jobs);

  function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function publicUser(user) {
    const safeUser = Object.fromEntries(
      Object.entries(user)
        .filter(([key]) => !/password|secret|token|credential|api.?key/i.test(key) && key !== '_id'),
    );
    return { ...safeUser, id: user._id.toString() };
  }

  function publicJob(job) {
    function removePrivateFields(value) {
      if (Array.isArray(value)) {
        return value.map(removePrivateFields);
      }
      if (!isRecord(value) || value instanceof ObjectId || value instanceof Date) {
        return value;
      }
      return Object.fromEntries(
        Object.entries(value)
          .filter(([key]) => !/email|phone|mobile|password|secret|token|applicant|recruiterId|userId|ownerId|resume|contact/i.test(key))
          .map(([key, nestedValue]) => [key, removePrivateFields(nestedValue)]),
      );
    }
    return removePrivateFields(job);
  }

  function validateId(id) {
    if (typeof id !== 'string' || !ObjectId.isValid(id)) {
      return null;
    }
    return new ObjectId(id);
  }

  function imageTypeMatches(file) {
    const buffer = file.buffer;
    switch (file.mimetype) {
      case 'image/jpeg':
        return buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
      case 'image/png':
        return buffer.length >= 8
          && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
      case 'image/gif':
        return buffer.length >= 6
          && ['GIF87a', 'GIF89a'].includes(buffer.subarray(0, 6).toString('ascii'));
      case 'image/webp':
        return buffer.length >= 12
          && buffer.subarray(0, 4).toString('ascii') === 'RIFF'
          && buffer.subarray(8, 12).toString('ascii') === 'WEBP';
      default:
        return false;
    }
  }

  const imageUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_IMAGE_SIZE, files: 1 },
    fileFilter(req, file, callback) {
      if (!allowedImageTypes.has(file.mimetype)) {
        return callback(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'image'));
      }
      return callback(null, true);
    },
  });

  app.get('/', (req, res) => {
    res.send('Hire loop is looping!');
  });

  app.post('/auth/login', async (req, res) => {
    if (!isRecord(req.body)
      || typeof req.body.email !== 'string'
      || typeof req.body.password !== 'string'
      || !req.body.email.trim()
      || !req.body.password) {
      return res.status(400).send({ message: 'Email and password are required' });
    }

    const email = req.body.email.trim();
    const user = await users.findOne({
      email: { $regex: `^${escapeRegex(email)}$`, $options: 'i' },
    });

    if (!user || typeof user.passwordHash !== 'string'
      || !await bcrypt.compare(req.body.password, user.passwordHash)) {
      return res.status(401).send({ message: 'Invalid email or password' });
    }

    if (typeof user.role !== 'string' || !user.role) {
      return res.status(403).send({ message: 'User role is not configured' });
    }

    return res.status(200).send({
      token: createAccessToken(user, jwtSecret),
      tokenType: 'Bearer',
      expiresIn: TOKEN_EXPIRES_IN_SECONDS,
      user: publicUser(user),
    });
  });

  app.get('/users', authenticate, verifyAdmin, async (req, res) => {
    const result = await users.find({}, { projection: { passwordHash: 0 } }).toArray();
    return res.status(200).send(result.map(publicUser));
  });

  app.get('/users/:id/premium', authenticate, async (req, res) => {
    const userId = validateId(req.params.id);
    if (!userId) {
      return res.status(400).send({ message: 'Invalid user id' });
    }
    if (req.user.role !== 'admin' && !userId.equals(req.user._id)) {
      return res.status(403).send({ message: 'You may only view your own profile' });
    }

    const result = await users.findOne({ _id: userId }, { projection: { premium: 1 } });
    if (!result) {
      return res.status(404).send({ message: 'User not found' });
    }
    return res.status(200).send({ premium: Boolean(result.premium) });
  });

  app.put('/users/me/profile-image', authenticate, imageUpload.single('image'), async (req, res) => {
    if (!req.file) {
      return res.status(400).send({ message: 'An image file is required' });
    }
    if (!imageTypeMatches(req.file)) {
      return res.status(400).send({ message: 'Image content does not match its file type' });
    }
    if (!imgbbApiKey) {
      return res.status(503).send({ message: 'Profile image upload is not configured' });
    }

    const form = new FormData();
    form.append('image', new Blob([req.file.buffer], { type: req.file.mimetype }), 'profile-image');
    let response;
    try {
      response = await fetch(
        `https://api.imgbb.com/1/upload?key=${encodeURIComponent(imgbbApiKey)}`,
        { method: 'POST', body: form, signal: AbortSignal.timeout(15000) },
      );
    } catch (error) {
      console.error('ImgBB upload request failed');
      return res.status(502).send({ message: 'Profile image service is unavailable' });
    }

    let uploadResult;
    try {
      uploadResult = await response.json();
    } catch (error) {
      return res.status(502).send({ message: 'Profile image service returned an invalid response' });
    }
    if (!response.ok || uploadResult?.success !== true || typeof uploadResult?.data?.url !== 'string') {
      return res.status(502).send({ message: 'Profile image upload failed' });
    }

    const imageUrl = uploadResult.data.url;
    const updateResult = await users.updateOne(
      { _id: req.user._id },
      { $set: { profileImage: imageUrl, updatedAt: new Date() } },
    );
    if (updateResult.matchedCount === 0) {
      return res.status(404).send({ message: 'User not found' });
    }

    return res.status(200).send({ profileImage: imageUrl });
  });

  app.patch('/users/:id/role', authenticate, verifyAdmin, async (req, res) => {
    const userId = validateId(req.params.id);
    if (!userId) {
      return res.status(400).send({ message: 'Invalid user id' });
    }
    const allowedRoles = new Set(['job_seeker', 'recruiter', 'admin']);
    if (!isRecord(req.body) || !allowedRoles.has(req.body.role)) {
      return res.status(400).send({ message: 'A valid role is required' });
    }

    const result = await users.updateOne({ _id: userId }, { $set: { role: req.body.role } });
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'User not found' });
    }
    return res.status(200).send({ message: 'User role updated' });
  });

  app.get('/jobs', async (req, res) => {
    const query = {};

    if (typeof req.query.jobType === 'string') {
      query.type = req.query.jobType;
    } else if (typeof req.query.type === 'string') {
      query.type = req.query.type;
    }
    if (req.query.remote === 'true' || req.query.remote === 'false') {
      query.remote = req.query.remote === 'true';
    }
    if (typeof req.query.category === 'string') {
      query.category = { $regex: escapeRegex(req.query.category.trim()), $options: 'i' };
    }
    if (typeof req.query.search === 'string') {
      const searchText = escapeRegex(req.query.search.trim());
      query.$or = [
        { title: { $regex: searchText, $options: 'i' } },
        { description: { $regex: searchText, $options: 'i' } },
        { company: { $regex: searchText, $options: 'i' } },
        { requirements: { $regex: searchText, $options: 'i' } },
      ];
    }

    const result = await jobs.find(query).toArray();
    return res.status(200).send(result.map(publicJob));
  });

  app.post('/jobs', authenticate, verifyRecruiter, async (req, res) => {
    if (!isRecord(req.body) || typeof req.body.title !== 'string' || !req.body.title.trim()) {
      return res.status(400).send({ message: 'Job title is required' });
    }

    const { _id, recruiterId, ...jobFields } = req.body;
    const job = {
      ...jobFields,
      title: req.body.title.trim(),
      recruiterId: req.user._id,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const result = await jobs.insertOne(job);
    return res.status(201).send({
      acknowledged: result.acknowledged,
      insertedId: result.insertedId.toString(),
    });
  });

  app.get('/jobs/:id', async (req, res) => {
    const jobId = validateId(req.params.id);
    if (!jobId) {
      return res.status(400).send({ message: 'Invalid job id' });
    }
    const result = await jobs.findOne({ _id: jobId });
    if (!result) {
      return res.status(404).send({ message: 'Job not found' });
    }
    return res.status(200).send(publicJob(result));
  });

  app.patch('/jobs/:id', authenticate, verifyRecruiter, verifyRecruiterJobOwnership, async (req, res) => {
    if (!isRecord(req.body)) {
      return res.status(400).send({ message: 'A job update is required' });
    }
    const { _id, recruiterId, createdAt, ...jobFields } = req.body;
    if (Object.keys(jobFields).length === 0) {
      return res.status(400).send({ message: 'A job update is required' });
    }
    if (jobFields.title !== undefined
      && (typeof jobFields.title !== 'string' || !jobFields.title.trim())) {
      return res.status(400).send({ message: 'Job title must be a non-empty string' });
    }
    if (typeof jobFields.title === 'string') {
      jobFields.title = jobFields.title.trim();
    }

    const result = await jobs.updateOne(
      {
        _id: req.job._id,
        recruiterId: { $in: [req.user._id, req.user._id.toString()] },
      },
      { $set: { ...jobFields, updatedAt: new Date() } },
    );
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Job not found' });
    }
    return res.status(200).send({ message: 'Job updated successfully' });
  });

  app.delete('/jobs/:id', authenticate, verifyRecruiter, verifyRecruiterJobOwnership, async (req, res) => {
    const result = await jobs.deleteOne({
      _id: req.job._id,
      recruiterId: { $in: [req.user._id, req.user._id.toString()] },
    });
    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'Job not found' });
    }
    return res.status(200).send({ message: 'Job deleted successfully' });
  });

  app.post('/applications', authenticate, verifyJobSeeker, async (req, res) => {
    if (!isRecord(req.body)) {
      return res.status(400).send({ message: 'Application details are required' });
    }
    const jobId = validateId(req.body.jobId);
    if (!jobId) {
      return res.status(400).send({ message: 'A valid jobId is required' });
    }

    const job = await jobs.findOne({ _id: jobId }, { projection: { _id: 1 } });
    if (!job) {
      return res.status(404).send({ message: 'Job not found' });
    }

    const alreadyApplied = await applications.findOne({
      $or: [
        { applicantId: req.user._id, jobId },
        {
          userId: { $in: [req.user._id, req.user._id.toString()] },
          jobId: { $in: [jobId, jobId.toString()] },
        },
      ],
    });
    if (alreadyApplied) {
      return res.status(409).send({ message: 'You have already applied for this job' });
    }

    const {
      _id,
      jobId: ignoredJobId,
      applicantId,
      userId,
      recruiterId,
      role,
      createdAt,
      ...applicationFields
    } = req.body;
    try {
      const result = await applications.insertOne({
        ...applicationFields,
        jobId,
        applicantId: req.user._id,
        createdAt: new Date(),
      });
      return res.status(201).send({ insertedId: result.insertedId.toString() });
    } catch (error) {
      if (error?.code === 11000) {
        return res.status(409).send({ message: 'You have already applied for this job' });
      }
      throw error;
    }
  });

  app.get('/applications', authenticate, verifyJobSeeker, async (req, res) => {
    const userId = req.user._id;
    const result = await applications.find({
      $or: [
        { applicantId: userId },
        { userId: { $in: [userId, userId.toString()] } },
      ],
    }).toArray();
    return res.status(200).send(result);
  });

  app.get('/applications/count', authenticate, verifyJobSeeker, async (req, res) => {
    const userId = req.user._id;
    const count = await applications.countDocuments({
      $or: [
        { applicantId: userId },
        { userId: { $in: [userId, userId.toString()] } },
      ],
    });
    return res.status(200).send({ count });
  });

  app.get(
    '/jobs/:id/applications',
    authenticate,
    verifyRecruiter,
    verifyRecruiterJobOwnership,
    async (req, res) => {
      const result = await applications.find({
        jobId: { $in: [req.job._id, req.job._id.toString()] },
      }).toArray();
      return res.status(200).send(result);
    },
  );

  app.get('/admin/jobs', authenticate, verifyAdmin, async (req, res) => {
    const result = await jobs.find({}).toArray();
    return res.status(200).send(result);
  });

  app.patch('/admin/jobs/:id', authenticate, verifyAdmin, async (req, res) => {
    const jobId = validateId(req.params.id);
    if (!jobId) {
      return res.status(400).send({ message: 'Invalid job id' });
    }
    if (!isRecord(req.body)) {
      return res.status(400).send({ message: 'A job update is required' });
    }
    const { _id, createdAt, ...jobFields } = req.body;
    if (Object.keys(jobFields).length === 0) {
      return res.status(400).send({ message: 'A job update is required' });
    }
    const result = await jobs.updateOne(
      { _id: jobId },
      { $set: { ...jobFields, updatedAt: new Date() } },
    );
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Job not found' });
    }
    return res.status(200).send({ message: 'Job updated successfully' });
  });

  app.delete('/admin/jobs/:id', authenticate, verifyAdmin, async (req, res) => {
    const jobId = validateId(req.params.id);
    if (!jobId) {
      return res.status(400).send({ message: 'Invalid job id' });
    }
    const result = await jobs.deleteOne({ _id: jobId });
    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'Job not found' });
    }
    return res.status(200).send({ message: 'Job deleted successfully' });
  });

  app.get('/admin/applications', authenticate, verifyAdmin, async (req, res) => {
    const result = await applications.find({}).toArray();
    return res.status(200).send(result);
  });

  app.delete('/admin/applications/:id', authenticate, verifyAdmin, async (req, res) => {
    const applicationId = validateId(req.params.id);
    if (!applicationId) {
      return res.status(400).send({ message: 'Invalid application id' });
    }
    const result = await applications.deleteOne({ _id: applicationId });
    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'Application not found' });
    }
    return res.status(200).send({ message: 'Application deleted successfully' });
  });

  app.post('/payments/checkout-verify', authenticate, async (req, res) => {
    if (!isRecord(req.body) || typeof req.body.sessionId !== 'string' || !req.body.sessionId) {
      return res.status(400).send({ message: 'Session ID is required' });
    }

    const session = await stripe.checkout.sessions.retrieve(req.body.sessionId);
    if (session.status !== 'complete' || session.payment_status !== 'paid') {
      return res.status(400).send({ success: false, message: 'Payment verification failed' });
    }
    if (!ObjectId.isValid(session.metadata?.userId)
      || session.metadata.userId !== req.user._id.toString()) {
      return res.status(403).send({ message: 'This payment session does not belong to you' });
    }

    const existingPayment = await payments.findOne({ sessionId: req.body.sessionId });
    if (existingPayment) {
      return res.status(200).send({ success: false, message: 'Payment already verified' });
    }

    const payment = {
      status: session.status,
      payment_status: session.payment_status,
      customer_email: session.customer_email,
      userId: req.user._id,
      payment_date: new Date(),
      payment_intent: session.payment_intent,
      sessionId: req.body.sessionId,
    };
    const result = await payments.insertOne(payment);
    await users.updateOne({ _id: req.user._id }, { $set: { premium: true } });
    return res.status(200).send({ success: true, paymentId: result.insertedId.toString() });
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) {
      return next(error);
    }
    if (error instanceof multer.MulterError) {
      const status = error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      return res.status(status).send({
        message: status === 413 ? 'Image exceeds the 5 MB limit' : 'Invalid image upload',
      });
    }
    if (error?.type === 'entity.too.large') {
      return res.status(413).send({ message: 'Request body is too large' });
    }
    console.error('Request failed', error?.name || 'Error');
    return res.status(500).send({ message: 'Internal server error' });
  });

  return app;
}
