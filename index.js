import 'dotenv/config';
import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors';
import Stripe from 'stripe'

const stripe =new Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB connection
const uri = process.env.MONGO_DB_URI;

if (!uri) {
  throw new Error('MONGO_DB_URI is missing from environment variables');
}

const client = new MongoClient(uri);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log('✅ You successfully connected to MongoDB!');
    return client;
  } catch (err) {
    console.error('❌ MongoDB Connection Error:', err);
    throw err; 
  }
}

const connectedClient = await connectToMongoDB();

// Database and Collections definition
const database = connectedClient.db('hrieloopprojectdb');
const users = database.collection('user');
const jobs = database.collection('jobs');
const payments = database.collection('payments');

// Helper: Escape special regex characters
function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Home API
app.get('/', (req, res) => {
  res.send('Hire loop is looping!');
});

// Users API
app.get('/users', async (req, res) => {
  try {
    const result = await users.find({}).toArray();
    res.send(result);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).send({ message: 'Failed to get users' });
  }
});

// Jobs GET API
app.get('/jobs', async (req, res) => {
  try {
    const query = {};

    if (req.query.jobType) {
      query.type = req.query.jobType;
    } else if (req.query.type) {
      query.type = req.query.type;
    }

    if (req.query.remote === 'true' || req.query.remote === 'false') {
      query.remote = req.query.remote === 'true';
    }

    if (req.query.category) {
      const category = escapeRegex(req.query.category.trim());
      query.category = {
        $regex: category,
        $options: 'i',
      };
    }

    if (req.query.search) {
      const searchText = escapeRegex(req.query.search.trim());

      query.$or = [
        { title: { $regex: searchText, $options: 'i' } },
        { description: { $regex: searchText, $options: 'i' } },
        { company: { $regex: searchText, $options: 'i' } },
        { requirements: { $regex: searchText, $options: 'i' } },
      ];
    }

    const result = await jobs.find(query).toArray();
    return res.status(200).send(result);

  } catch (error) {
    console.error('Error fetching jobs:', error);
    return res.status(500).send({ message: 'Failed to fetch jobs' });
  }
});

// Jobs POST API
app.post('/jobs', async (req, res) => {
  try {
    const job = req.body;
    const result = await jobs.insertOne(job);

    res.status(201).send({
      acknowledged: result.acknowledged,
      insertedId: result.insertedId.toString(),
    });

  } catch (error) {
    console.error('Error creating job:', error);
    res.status(500).send({ message: 'Failed to create job' });
  }
});

// Jobs Details Page API
app.get('/jobs/:id', async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: 'Invalid job id' });
    }
    const query = { _id: new ObjectId(id) };
    const result = await jobs.findOne(query);
    
    if (!result) {
      return res.status(404).send({ message: 'Job not found' });
    }
    res.send(result);
  } catch (error) {
    console.error('Error fetching job details:', error);
    res.status(500).send({ message: 'Failed to get job details' });
  }
});

// Jobs DELETE API
app.delete('/jobs/:id', async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) {
    return res.status(400).send({ message: 'Invalid job id' });
  }

  try {
    const result = await jobs.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'Job not found' });
    }

    return res.status(200).send({
      message: 'Job deleted successfully',
    });

  } catch (error) {
    console.error('Error deleting job:', error);
    return res.status(500).send({ message: 'Failed to delete job' });
  }
});

// Applications POST API
// Applications POST API
app.post('/applications', async (req, res) => {
  try {
    const application = req.body;
    const result = await applications.insertOne(application);
    res.status(201).send(result);
  } catch (error) {
    console.error('Error saving application:', error);
    res.status(500).send({ message: 'Failed to submit application' });
  }
});


// Applications GET API
app.get('/applications', async (req, res) => {
  try {
    const query = {};
    if (req.query.userId) {
      query.userId = req.query.userId;
    }
    const result = await applications.find(query).toArray();
    res.status(200).send(result);
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).send({ message: 'Failed to fetch applications' });
  }
});



// count

app.get('/applications/count', async (req, res) => {
  try {
    const query = {};
    if (req.query.userId) {
      query.userId = req.query.userId;
    }
 
    const result = await applications.countDocuments(query)
   
    res.send({count:result})

  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).send({ message: 'Failed to fetch applications' });
  }
});


// payments related api

app.post('/payments/checkout-verify', async (req, res) => {
  try {
    const { sessionId } = req.body;
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.status === 'complete' && session.payment_status === 'paid') {
      const { status, payment_status, customer_email, metadata, payment_intent } = session;

      // ১. পেমেন্ট রেকর্ড সেভ করা
      const result = await payments.insertOne({
        status,
        payment_status,
        customer_email,
        userId: metadata?.userId,
        payment_date: new Date(),
        payment_intent,
        sessionId,
      });

      // ২. ইউজারের প্রিমিয়াম স্ট্যাটাস আপডেট করা
      const updateResult = await users.updateOne(
        { _id: new ObjectId(metadata.userId) },
        { $set: { premium: true } }
      );

      return res.send({ success: true, result, updateResult });
      return
    }

    res.send({ success: false, message: 'Payment verification failed' });
  } catch (error) {
    res.status(500).send({ success: false, error: error.message });
  }
});


// Start server
app.listen(port, () => {
  console.log(`🚀 Server is listening on port ${port}`);
});