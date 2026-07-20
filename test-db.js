const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
  const uri = process.env.MONGODB_URI;
  const client = new MongoClient(uri);
  try {
    await client.connect();
    console.log("Connected");
    const db = client.db(process.env.MONGODB_DB || "shortly_agents");
    
    const admins = await db.collection("admin_users").find().toArray();
    console.log("Admins:");
    console.dir(admins, { depth: null });
    
    const agents = await db.collection("agent_logins").find().toArray();
    console.log("Agent Logins:", agents.length);
    console.dir(agents, { depth: null });
  } finally {
    await client.close();
  }
}
run().catch(console.dir);
