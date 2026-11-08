import 'dotenv/config'; // এটি সবার উপরে থাকতেই হবে
import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors';

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(express.json());
app.use(cors());

// চেক করা হচ্ছে URI ঠিকমতো আসছে কিনা
const uri = process.env.MONGO_DB_URI;


const client = new MongoClient(uri);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("✅ You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err);
  }
}

// কানেকশন ফাংশনটি এখানে কল করে দিচ্ছি যাতে সার্ভার চালু হলেই কানেক্ট হয়
// connectToMongoDB();

// export async function disconnectFromMongoDB() {
//   await client.close();
// }

const connectedClient = await connectToMongoDB();
const database= connectedClient.db("hrieloopprojectdb");
const users =database.collection("user")
const jobs = database.collection("jobs");


app.get('/', (req, res) => {
  res.send('Hire loop is looping!');
});


// 1st api 

app.get('/users', async (req, res) => {
  try {
    const cursor = users.find({});
    const result = await cursor.toArray();
    res.send(result);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).send({ message: "Failed to get users" });
  }
});

//jobs related apis

app.get('/jobs', async(req,res)=>{
  const cursor = jobs.find();
  const result = await cursor.toArray();
  res.send(result)
})


app.post('/jobs', async(req,res)=>{
    const job = req.body;
    const result =await jobs.insertOne(job);
    res.send(result)
})

app.delete('/jobs/:id', async (req, res) => {
  const { id } = req.params;

  if (!/^[\da-f]{24}$/i.test(id)) {
    return res.status(400).send({ message: 'Invalid job id' });
  }

  try {
    const result = await jobs.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'Job not found' });
    }

    return res.status(200).send({ message: 'Job deleted successfully' });
  } catch (error) {
    console.error('Error deleting job:', error);
    return res.status(500).send({ message: 'Failed to delete job' });
  }
});



app.listen(port, () => {
  console.log(`🚀 Example app listening on port ${port}`);
});