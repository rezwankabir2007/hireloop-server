import 'dotenv/config';
import { MongoClient } from 'mongodb';
import Stripe from 'stripe';
import { createApp } from './app.js';

const port = process.env.PORT || 5000;
const jwtSecret = process.env.JWT_SECRET;
const mongoUri = process.env.MONGO_DB_URI;

if (!jwtSecret || Buffer.byteLength(jwtSecret) < 32) {
  throw new Error('JWT_SECRET must be set to a secret of at least 32 bytes');
}
if (!mongoUri) {
  throw new Error('MONGO_DB_URI is missing from environment variables');
}

const client = new MongoClient(mongoUri);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    return client;
  } catch (error) {
    console.error('MongoDB connection failed:', error?.name || 'Error');
    throw new Error('MongoDB connection failed');
  }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db('hrieloopprojectdb');
const users = database.collection('user');
const jobs = database.collection('jobs');
const payments = database.collection('payments');
const applications = database.collection('applications');

await applications.createIndex(
  { applicantId: 1, jobId: 1 },
  {
    unique: true,
    partialFilterExpression: {
      applicantId: { $type: 'objectId' },
      jobId: { $type: 'objectId' },
    },
  },
);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = createApp({
  users,
  jobs,
  payments,
  applications,
  stripe,
  jwtSecret,
  imgbbApiKey: process.env.IMGBB_API_KEY,
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
