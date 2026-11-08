import 'dotenv/config'; // এটি সবার উপরে থাকতেই হবে
import express from 'express';
import { MongoClient } from 'mongodb';
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

app.post('/jobs', async(req,res)=>{
    const job = req.body;
    const result =await jobs.insertOne(job);
    res.send(result)
})



app.listen(port, () => {
  console.log(`🚀 Example app listening on port ${port}`);
});