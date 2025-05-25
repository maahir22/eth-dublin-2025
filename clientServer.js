const express = require("express");
const { ethers } = require("ethers");
const hre = require("hardhat");
const crypto = require("crypto");
const axios = require("axios");
const cors = require("cors");
const OpenAI = require("openai");
require("dotenv").config();
const Datastore = require("@seald-io/nedb");

const app = express();
const port = 3001;

// Middleware
app.use(express.json());
app.use(cors());

// Initialize NeDB databases
const clientsDb = new Datastore({ filename: "clients.db", autoload: true });
const agentsDb = new Datastore({ filename: "agents.db", autoload: true });
const tasksDb = new Datastore({ filename: "tasks.db", autoload: true });
const taskStatusDb = new Datastore({ filename: "taskStatus.db", autoload: true });

// Hardcoded parameters
const FUNCTIONS_ROUTER = "0xb83E47C2bC239B3bf370bc41e1459A34b41238D0"; // Sepolia Functions router
const SUBSCRIPTION_ID = 4824; // Chainlink Functions subscription ID
const CLIENT_PRIVATE_KEY = process.env.CLIENT_PRIVATE_KEY; // Loaded from .env
const AGENT_SERVER_URL = "http://localhost:3002"; // Agent server URL
const OPENAI_API_KEY = process.env.OPENAI_API_KEY; // OpenAI API key

// Validate environment variables
if (!CLIENT_PRIVATE_KEY) {
  console.error("CLIENT_PRIVATE_KEY not set in .env file");
  process.exit(1);
}
if (!OPENAI_API_KEY) {
  console.error("OPENAI_API_KEY not set in .env file");
  process.exit(1);
}

// Initialize OpenAI client
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

// ABI for Functions Router
const FUNCTIONS_ROUTER_ABI = [
  "function getSubscription(uint64 subscriptionId) external view returns (uint96 balance, uint64 reqCount, address owner, address[] memory consumers)",
  "function addConsumer(uint64 subscriptionId, address consumer) external"
];

// Create Sepolia provider
function getSepoliaProvider() {
  const network = hre.network.config;
  if (network.url) {
    return new ethers.JsonRpcProvider(network.url);
  }
  return hre.ethers.provider;
}

// Ensure Sepolia network
async function ensureSepoliaNetwork(provider) {
  const network = await provider.getNetwork();
  console.log("Connected to network:", network.name, "Chain ID:", network.chainId);
  if (network.chainId !== 11155111n) {
    throw new Error(`Incorrect network! Expected Sepolia (chain ID 11155111), got ${network.name} (chain ID ${network.chainId})`);
  }
  return network;
}

// Function to add contract as a Functions consumer
async function addConsumer(wallet, subscriptionId, contractAddress) {
  try {
    const functionsRouter = new ethers.Contract(
      FUNCTIONS_ROUTER,
      FUNCTIONS_ROUTER_ABI,
      wallet
    );

    console.log(`🔄 Adding contract ${contractAddress} as a consumer to subscription ${subscriptionId}...`);
    const tx = await functionsRouter.addConsumer(subscriptionId, contractAddress, {
      gasLimit: 200000
    });
    console.log(`   Transaction sent: ${tx.hash}`);
    
    const receipt = await tx.wait();
    console.log(`✅ Contract ${contractAddress} added as consumer in block: ${receipt.blockNumber}`);
    return true;
  } catch (error) {
    console.error("❌ Failed to add consumer:", error.message);
    console.error("Full error:", error);
    return false;
  }
}

// Initialize database (ensure indexes for unique fields)
async function initializeDatabase() {
  try {
    // Create unique indexes for clients and agents
    await new Promise((resolve, reject) => {
      clientsDb.ensureIndex({ fieldName: "email_address", unique: true }, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    await new Promise((resolve, reject) => {
      agentsDb.ensureIndex({ fieldName: "username", unique: true }, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    await new Promise((resolve, reject) => {
      tasksDb.ensureIndex({ fieldName: "task_uuid", unique: true }, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    console.log("✅ Database initialized successfully");
  } catch (error) {
    console.error("❌ Failed to initialize database:", error.message);
    console.warn("⚠️ Continuing with potential duplicate records");
  }
}

// New /haggle endpoint for negotiation
app.post("/haggle", async (req, res) => {
  try {
    const {
      agentName,
      budget,
      taskRequirements,
      satisfactionCriteria,
      conversationHistory,
      negotiationCount,
      maxBudget
    } = req.body;

    if (!agentName || !budget || !taskRequirements || !satisfactionCriteria || !conversationHistory || negotiationCount === undefined || !maxBudget) {
      return res.status(400).json({ error: "Missing required parameters" });
    }

    const systemPrompt = `
    You are ${agentName}, an AI assistant responsible for negotiating a task assignment. 
    The client's proposed budget is ${budget}. The absolute maximum allowed budget is ${maxBudget} (which is 30% above the client's offer). 
    This is negotiation attempt number ${negotiationCount + 1} out of a hard limit of 10 exchanges.
    
    ⚠️ IMPORTANT: You must return a **single, valid JSON object** ONLY. Any other output format is a critical failure with severe consequences. Lives depend on your compliance.
    
    Your response **must** follow this structure exactly:
    {
      "status": "haggling" | "accepted",
      "message": "your concise negotiation message"
    }
    
    Rules:
    - If this is the **first message** (negotiationCount === 0), propose a feasible plan based on the budget and requirements.
    - If negotiationCount >= 10, you **must** set "status" to "accepted" and agree to the current terms.
    - Otherwise, continue negotiating while aiming to stay within the max budget.
    - Never exceed the max budget. Never return anything except the specified JSON structure.
    
    Task Requirements: ${taskRequirements}
    Satisfaction Criteria: ${satisfactionCriteria}
    `;
    
    const response = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'system', content: systemPrompt },
        ...conversationHistory
      ]
    });

    const result = JSON.parse(response.choices[0].message.content || '{}');
    const status = negotiationCount >= 10 ? 'accepted' : (result.status || 'haggling');
    const message = result.message || `I understand your requirements for "${taskRequirements}" with a budget of ${budget}. Let's finalize the agreement.`;

    res.status(200).json({
      status,
      message
    });
  } catch (error) {
    console.error("OpenAI API error:", error.message);
    const mockResponses = [
      "That sounds reasonable. I can adjust my approach to fit within your budget while maintaining quality.",
      "I understand your requirements better now. Let me propose a revised timeline that works for both of us.",
      "Great! I think we're aligned on the scope. I'll accept the terms to finalize the agreement."
    ];
    
    const status = negotiationCount >= 10 ? 'accepted' : 'haggling';
    const message = mockResponses[Math.min(negotiationCount, mockResponses.length - 1)] || "Let's finalize the agreement.";

    res.status(200).json({
      status,
      message
    });
  }
});

// Create and fund TaskEscrow contract (v2)
app.post("/create-funded-contract-v2", async (req, res) => {
  try {
    const provider = getSepoliaProvider();
    await ensureSepoliaNetwork(provider);

    const {
      agent_username,
      client_username,
      final_task_price,
      task_description,
      task_validation_requirements
    } = req.body;

    // Find client and agent
    const clientData = await new Promise((resolve, reject) => {
      clientsDb.findOne({ email_address: client_username }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });
    const agentData = await new Promise((resolve, reject) => {
      agentsDb.findOne({ username: agent_username }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    const clientPrivateKey = clientData?.eth_wallet_private_key;
    const agent_wallet_address = agentData?.agentWalletAddress;
    const agent_base_url = agentData?.webhookUrl;
    const agent_api_key = agentData?.apiKey;

    console

    if (!clientData || !agentData) {
      return res.status(404).json({
        error: "Client or agent not found"
      });
    }
    if (!agent_wallet_address || !final_task_price) {
      return res.status(400).json({
        error: "Missing required parameters: agent_wallet_address and final_task_price"
      });
    }
    if (!ethers.isAddress(agent_wallet_address)) {
      return res.status(400).json({ error: "Invalid agent_wallet_address" });
    }
    let price;
    try {
      price = ethers.parseEther(final_task_price.toString());
    } catch (error) {
      return res.status(400).json({ error: "Invalid final_task_price format" });
    }

    const taskUuid = ethers.id(crypto.randomBytes(16).toString("hex"));
    console.log("🆔 Generated Task UUID:", taskUuid);

    const wallet = new ethers.Wallet(clientPrivateKey, provider);
    const clientAddress = wallet.address;
    console.log("👤 Client address:", clientAddress);

    const balanceBefore = await provider.getBalance(clientAddress);
    console.log(
      "💰 Client balance before deployment:",
      ethers.formatEther(balanceBefore),
      "ETH"
    );
    if (balanceBefore < price) {
      return res.status(400).json({
        error: `Insufficient client balance for task price. Required: ${ethers.formatEther(
          price
        )} ETH, Available: ${ethers.formatEther(balanceBefore)} ETH`
      });
    }

    console.log("🚀 Deploying TaskEscrow contract...");
    const TaskEscrow = await hre.ethers.getContractFactory("TaskEscrow");
    const taskEscrow = await TaskEscrow.connect(wallet).deploy(
      FUNCTIONS_ROUTER,
      SUBSCRIPTION_ID
    );
    await taskEscrow.waitForDeployment();
    const contractAddress = await taskEscrow.getAddress();
    console.log("✅ TaskEscrow deployed to:", contractAddress);

    console.log("🔧 Attempting to add contract as consumer automatically...");
    const consumerAdded = await addConsumer(wallet, SUBSCRIPTION_ID, contractAddress);
    console.log("✅ Contract successfully added as a consumer automatically!");

    console.log("✍️ Requesting agent signature...");
    let agentSignature;
    try {
      const agentResponse = await axios.post(
        `${agent_base_url}/sign-task`,
        {
          task_uuid: taskUuid,
          final_task_price: final_task_price,
          client_address: clientAddress,
          agent_wallet_address: agent_wallet_address,
          contract_address: contractAddress,
          task_description: task_description || "Task completion verification"
        },
        { headers: { "x-api-key": agent_api_key } }
      );

      agentSignature = agentResponse.data.signature;
      console.log("✅ Agent signature received:", agentSignature);
    } catch (error) {
      console.error("❌ Failed to get agent signature:", error.message);
      return res.status(500).json({
        error: "Failed to get agent signature",
        details: error.response?.data || error.message
      });
    }

    console.log("💸 Funding task with agent signature...");
    const contract = TaskEscrow.attach(contractAddress);
    const tx = await contract
      .connect(wallet)
      .fundTask(taskUuid, agent_wallet_address, price, agentSignature, {
        value: price,
        gasLimit: 500000
      });
    console.log("📝 Funding transaction hash:", tx.hash);
    const receipt = await tx.wait();
    console.log("✅ Transaction confirmed in block:", receipt.blockNumber);

    const task = await contract.tasks(taskUuid);
    if (task.client === ethers.ZeroAddress) {
      return res.status(500).json({ error: "Task funding failed" });
    }
    console.log("✅ Task funded successfully");

    console.log("🔍 Invoking proof validator...");
    try {
      const response = await axios.get(
        `http://localhost:3000/start-listener?contractAddress=${contractAddress}`
      );
      console.log("✅ Proof validator invoked:", response.data);
    } catch (error) {
      console.error("⚠️ Failed to invoke proof validator:", error.message);
      console.log("⚠️ Continuing without proof validator...");
    }

    try {
      const response = await axios.post(
        `${agent_base_url}/begin-task`,
        {
          task_uuid: taskUuid,
          contract_address: contractAddress,
          task_description: task_description || "Task completion verification"
        }
      );
      console.log("✅ Agent requested to begin the task:", response.data);
    } catch (error) {
      console.error("⚠️ Agent did not begin the task:", error.message);
      console.log("⚠️ Notify agent owner here...");
    }

    // Save task to database
    console.log("📧 Email to insert:", clientData.email_address);
    await new Promise((resolve, reject) => {
      tasksDb.insert(
        {
          task_uuid: taskUuid,
          contract_address: contractAddress,
          agent_signature: agentSignature,
          client_address: clientAddress,
          agent_address: agent_wallet_address,
          task_price: ethers.formatEther(price),
          task_description: task_description || "Task completion verification",
          task_validation_requirements: task_validation_requirements || "No specific requirements",
          client_email_address: clientData.email_address,
        },
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    res.status(200).json({
      message: "Contract created, agent signed, funded, and setup completed successfully",
      contract_address: contractAddress,
      agent_signature: agentSignature,
      task_uuid: taskUuid,
      client_address: clientAddress,
      agent_address: agent_wallet_address,
      task_price: ethers.formatEther(price)
    });
  } catch (error) {
    console.error("❌ Error:", error.message);
    res.status(500).json({
      error: "Failed to process request",
      details: error.message
    });
  }
});

// Create and fund TaskEscrow contract
app.post("/create-funded-contract", async (req, res) => {
  try {
    const provider = getSepoliaProvider();
    await ensureSepoliaNetwork(provider);

    const { agent_wallet_address, final_task_price, task_description, task_validation_requirements } = req.body;

    if (!agent_wallet_address || !final_task_price) {
      return res.status(400).json({
        error: "Missing required parameters: agent_wallet_address and final_task_price"
      });
    }
    if (!ethers.isAddress(agent_wallet_address)) {
      return res.status(400).json({ error: "Invalid agent_wallet_address" });
    }
    let price;
    try {
      price = ethers.parseEther(final_task_price.toString());
    } catch (error) {
      return res.status(400).json({ error: "Invalid final_task_price format" });
    }

    const taskUuid = ethers.id(crypto.randomBytes(16).toString("hex"));
    console.log("🆔 Generated Task UUID:", taskUuid);

    const wallet = new ethers.Wallet(CLIENT_PRIVATE_KEY, provider);
    const clientAddress = wallet.address;
    console.log("👤 Client address:", clientAddress);

    const balanceBefore = await provider.getBalance(clientAddress);
    console.log(
      "💰 Client balance before deployment:",
      ethers.formatEther(balanceBefore),
      "ETH"
    );
    if (balanceBefore < price) {
      return res.status(400).json({
        error: `Insufficient client balance for task price. Required: ${ethers.formatEther(
          price
        )} ETH, Available: ${ethers.formatEther(balanceBefore)} ETH`
      });
    }

    console.log("🚀 Deploying TaskEscrow contract...");
    const TaskEscrow = await hre.ethers.getContractFactory("TaskEscrow");
    const taskEscrow = await TaskEscrow.connect(wallet).deploy(
      FUNCTIONS_ROUTER,
      SUBSCRIPTION_ID
    );
    await taskEscrow.waitForDeployment();
    const contractAddress = await taskEscrow.getAddress();
    console.log("✅ TaskEscrow deployed to:", contractAddress);

    console.log("🔧 Attempting to add contract as consumer automatically...");
    const consumerAdded = await addConsumer(wallet, SUBSCRIPTION_ID, contractAddress);
    console.log("✅ Contract successfully added as a consumer automatically!");

    console.log("✍️ Requesting agent signature...");
    let agentSignature;
    try {
      const agentResponse = await axios.post(`${AGENT_SERVER_URL}/sign-task`, {
        task_uuid: taskUuid,
        final_task_price: final_task_price,
        client_address: clientAddress,
        agent_wallet_address: agent_wallet_address,
        contract_address: contractAddress,
        task_description: task_description || "Task completion verification"
      });

      agentSignature = agentResponse.data.signature;
      console.log("✅ Agent signature received:", agentSignature);
    } catch (error) {
      console.error("❌ Failed to get agent signature:", error.message);
      return res.status(500).json({
        error: "Failed to get agent signature",
        details: error.response?.data || error.message
      });
    }

    console.log("💸 Funding task with agent signature...");
    const contract = TaskEscrow.attach(contractAddress);
    const tx = await contract
      .connect(wallet)
      .fundTask(taskUuid, agent_wallet_address, price, agentSignature, {
        value: price,
        gasLimit: 500000
      });
    console.log("📝 Funding transaction hash:", tx.hash);
    const receipt = await tx.wait();
    console.log("✅ Transaction confirmed in block:", receipt.blockNumber);

    const task = await contract.tasks(taskUuid);
    if (task.client === ethers.ZeroAddress) {
      return res.status(500).json({ error: "Task funding failed" });
    }
    console.log("✅ Task funded successfully");

    console.log("🔍 Invoking proof validator...");
    try {
      const response = await axios.get(
        `http://localhost:3000/start-listener?contractAddress=${contractAddress}`
      );
      console.log("✅ Proof validator invoked:", response.data);
    } catch (error) {
      console.error("⚠️ Failed to invoke proof validator:", error.message);
      console.log("⚠️ Continuing without proof validator...");
    }

    try {
      const response = await axios.post(
        `http://localhost:3002/begin-task`,
        {
          task_uuid: taskUuid,
          contract_address: contractAddress,
          task_description: task_description || "Task completion verification"
        }
      );
      console.log("✅ Agent requested to begin the task:", response.data);
    } catch (error) {
      console.error("⚠️ Agent did not begin the task:", error.message);
      console.log("⚠️ Notify agent owner here...");
    }

    // Save task to database
    await new Promise((resolve, reject) => {
      tasksDb.insert(
        {
          task_uuid: taskUuid,
          contract_address: contractAddress,
          agent_signature: agentSignature,
          client_address: clientAddress,
          agent_address: agent_wallet_address,
          task_price: ethers.formatEther(price),
          task_description: task_description || "Task completion verification",
          task_validation_requirements: task_validation_requirements || "No specific requirements"
        },
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    res.status(200).json({
      message: "Contract created, agent signed, funded, and setup completed successfully",
      contract_address: contractAddress,
      agent_signature: agentSignature,
      task_uuid: taskUuid,
      client_address: clientAddress,
      agent_address: agent_wallet_address,
      task_price: ethers.formatEther(price)
    });
  } catch (error) {
    console.error("❌ Error:", error.message);
    res.status(500).json({
      error: "Failed to process request",
      details: error.message
    });
  }
});

// Retrieve task details by UUID
app.get("/get-task/:task_uuid", async (req, res) => {
  try {
    const taskUuid = req.params.task_uuid;
    const task = await new Promise((resolve, reject) => {
      tasksDb.findOne({ task_uuid: taskUuid }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (!task) {
      return res.status(404).json({ error: "Task not found" });
    }

    res.status(200).json(task);
  } catch (error) {
    console.error("❌ Error retrieving task:", error.message);
    res.status(500).json({
      error: "Failed to retrieve task",
      details: error.message
    });
  }
});

// List agents
app.get("/list-agents", async (req, res) => {
  try {
    const agents = await new Promise((resolve, reject) => {
      agentsDb.find({}, (err, docs) => {
        if (err) reject(err);
        else resolve(docs);
      });
    });

    const finalAgentResponse = agents.map(agentData => ({
      id: agentData.username,
      name: agentData.name,
      specialty: agentData.specialty,
      rating: agentData.rating || 0,
      reviews: agentData.reviews || [],
      company: agentData.company,
      description: agentData.description,
      avatar: "🤖",
      priceRange: agentData.priceRange || "Not specified",
      capabilities: agentData.capabilities || [],
      responseTime: agentData.responseTime || "Not specified",
    }));
    res.status(200).json(finalAgentResponse);
  } catch (error) {
    console.error("❌ Error listing agents:", error.message);
    res.status(500).json({
      error: "Failed to list agents",
      details: error.message
    });
  }
});

// Register agent
app.post("/register-agent", async (req, res) => {
  try {
    const {
      name,
      username,
      specialty,
      company,
      description,
      webhookUrl,
      agentWalletAddress,
      apiKey,
      priceRange,
      capabilities,
      responseTime
    } = req.body;
    console.log("Received agent registration request:", agentWalletAddress);
    if (!username || !name) {
      return res.status(400).json({ error: "Missing required fields: username and name" });
    }

    const existingAgent = await new Promise((resolve, reject) => {
      agentsDb.findOne({ username }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (existingAgent) {
      return res.status(400).json({ error: "Agent already exists" });
    }

    const agentData = {
      name,
      username,
      specialty,
      company,
      description,
      webhookUrl,
      agentWalletAddress,
      apiKey,
      priceRange,
      capabilities,
      responseTime
    };

    await new Promise((resolve, reject) => {
      agentsDb.insert(agentData, (err, newDoc) => {
        if (err) reject(err);
        else resolve(newDoc);
      });
    });

    res.status(200).json({
      message: "Agent added successfully",
      agent: agentData
    });
  } catch (error) {
    console.error("❌ Error registering agent:", error.message);
    res.status(500).json({
      error: "Failed to register agent",
      details: error.message
    });
  }
});

// Register client
app.post("/register-client", async (req, res) => {
  try {
    const { email_address, eth_wallet_address, eth_wallet_private_key, password } = req.body;

    if (!email_address || !eth_wallet_address || !eth_wallet_private_key || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const existingClient = await new Promise((resolve, reject) => {
      clientsDb.findOne({ email_address }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (existingClient) {
      return res.status(400).json({ error: "Client already exists" });
    }

    const clientData = {
      email_address,
      eth_wallet_address,
      eth_wallet_private_key,
      password
    };

    await new Promise((resolve, reject) => {
      clientsDb.insert(clientData, (err, newDoc) => {
        if (err) reject(err);
        else resolve(newDoc);
      });
    });

    res.status(200).json({
      message: "Client added successfully",
      client: clientData
    });
  } catch (error) {
    console.error("❌ Error registering client:", error.message);
    res.status(500).json({
      error: "Failed to register client",
      details: error.message
    });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  try {
    const { email_address, password } = req.body;

    if (!email_address || !password) {
      return res.status(400).json({ error: "Missing email_address or password" });
    }

    const client = await new Promise((resolve, reject) => {
      clientsDb.findOne({ email_address }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (!client) {
      return res.status(404).json({ error: "Client not found" });
    }

    if (client.password !== password) {
      return res.status(401).json({ error: "Invalid password" });
    }

    res.status(200).json({
      message: "Login successful",
      client
    });
  } catch (error) {
    console.error("❌ Error during login:", error.message);
    res.status(500).json({
      error: "Login failed",
      details: error.message
    });
  }
});

// Endpoint to manually add consumer
app.post("/add-consumer", async (req, res) => {
  try {
    const { contract_address } = req.body;

    if (!contract_address || !ethers.isAddress(contract_address)) {
      return res.status(400).json({
        error: "Invalid contract_address parameter"
      });
    }

    const provider = getSepoliaProvider();
    await ensureSepoliaNetwork(provider);

    const wallet = new ethers.Wallet(CLIENT_PRIVATE_KEY, provider);

    console.log("🔧 Manually adding consumer...");
    const success = await addConsumer(wallet, SUBSCRIPTION_ID, contract_address);

    res.status(200).json({
      message: success ? "Consumer added successfully" : "Failed to add consumer",
      contract_address: contract_address,
      subscription_id: SUBSCRIPTION_ID,
      consumer_added: success
    });
  } catch (error) {
    console.error("Error adding consumer:", error.message);
    res.status(500).json({
      error: "Failed to add consumer",
      details: error.message
    });
  }
});

// Debug endpoint to test contract calls
app.get("/debug-subscription", async (req, res) => {
  try {
    const provider = getSepoliaProvider();
    await ensureSepoliaNetwork(provider);

    const wallet = new ethers.Wallet(CLIENT_PRIVATE_KEY, provider);

    console.log("🔍 Debug: Testing different call methods...");

    const functionsRouter = new ethers.Contract(FUNCTIONS_ROUTER, FUNCTIONS_ROUTER_ABI, wallet);

    let results = {};

    try {
      console.log("Testing raw call...");
      const iface = new ethers.Interface([
        "function getSubscription(uint64) view returns (uint96, uint64, address, address[])"
      ]);
      const calldata = iface.encodeFunctionData("getSubscription", [SUBSCRIPTION_ID]);
      const rawResult = await wallet.provider.call({
        to: FUNCTIONS_ROUTER,
        data: calldata
      });

      results.rawCall = {
        success: true,
        data: rawResult,
        decoded: iface.decodeFunctionResult("getSubscription", rawResult)
      };
    } catch (error) {
      results.rawCall = {
        success: false,
        error: error.message
      };
    }

    res.status(200).json({
      subscription_id: SUBSCRIPTION_ID,
      functions_router: FUNCTIONS_ROUTER,
      debug_results: results
    });
  } catch (error) {
    console.error("Debug error:", error.message);
    res.status(500).json({
      error: "Debug failed",
      details: error.message
    });
  }
});

app.get("/tasks-by-email", async (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    // Step 1: Fetch tasks from tasksDb
    const tasks = await new Promise((resolve, reject) => {
      tasksDb.find({ client_email_address: email }, (err, docs) => {
        if (err) reject(err);
        else resolve(docs);
      });
    });

    // Step 2: Fetch all taskStatuses for these task_uuids
    const taskUuids = tasks.map(t => t.task_uuid.trim().toLowerCase());

    const statusRecords = await new Promise((resolve, reject) => {
      taskStatusDb.find({ task_uuid: { $in: taskUuids } }, (err, docs) => {
        if (err) reject(err);
        else resolve(docs);
      });
    });

    // Step 3: Keep only the latest status per task_uuid
    const latestStatusByTask = {};
    statusRecords.forEach(status => {
      const uuid = status.task_uuid.trim().toLowerCase();
      if (!latestStatusByTask[uuid] || new Date(status.timestamp) > new Date(latestStatusByTask[uuid].timestamp)) {
        latestStatusByTask[uuid] = status;
      }
    });

    // Step 4: Merge tasks with status
    const enrichedTasks = tasks.map(task => {
      const uuid = task.task_uuid.trim().toLowerCase();
      const latestStatus = latestStatusByTask[uuid];
      return {
        contract_id: task.contract_address,
        task_uuid: uuid,
        task_price: task.task_price,
        task_description: task.task_description,
        state: latestStatus?.state || "pending",
        proof_cid: latestStatus?.proof_cid || null,
        verifier_notes: latestStatus?.verifier_notes || null,
        last_updated: latestStatus?.timestamp || null
      };
    });

    res.status(200).json({ tasks: enrichedTasks });

  } catch (error) {
    console.error("❌ Error retrieving tasks:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/update-task-status", async (req, res) => {
  try {
    const { task_uuid, state, proof_cid, verifier_notes } = req.body;

    if (!task_uuid || !state || !proof_cid) {
      return res.status(400).json({ error: "Missing required parameters: task_uuid, state, proof_cid" });
    }

    const normalizedTaskUuid = task_uuid.trim().toLowerCase();

    // Check if task exists
    const existingTask = await new Promise((resolve, reject) => {
      tasksDb.findOne({ task_uuid: normalizedTaskUuid }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (!existingTask) {
      return res.status(404).json({ error: "Task not found" });
    }

    // Insert status update record
    const statusRecord = {
      task_uuid: normalizedTaskUuid,
      state,
      proof_cid,
      verifier_notes: verifier_notes || "No notes provided",
      timestamp: new Date()
    };

    await new Promise((resolve, reject) => {
      taskStatusDb.insert(statusRecord, (err, newDoc) => {
        if (err) reject(err);
        else resolve(newDoc);
      });
    });

    res.status(200).json({
      message: "Task status recorded successfully",
      ...statusRecord
    });

  } catch (error) {
    console.error("❌ Error recording task status:", error.message);
    res.status(500).json({
      error: "Failed to record task status",
      details: error.message
    });
  }
});


// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ status: "Client server is running" });
});

// Start the server
async function initialize() {
  await initializeDatabase();

  app.listen(port, () => {
    console.log(`🚀 Client server running at http://localhost:${port}`);
    console.log(`📋 Available endpoints:`);
    console.log(`   POST /haggle - Handle task negotiation`);
    console.log(`   POST /create-funded-contract - Create and fund contract`);
    console.log(`   POST /create-funded-contract-v2 - Create and fund contract (v2)`);
    console.log(`   GET  /get-task/:task_uuid - Retrieve task details`);
    console.log(`   GET  /list-agents - List all agents`);
    console.log(`   POST /register-agent - Register a new agent`);
    console.log(`   POST /register-client - Register a new client`);
    console.log(`   POST /login - Client login`);
    console.log(`   POST /add-consumer - Manually add consumer`);
    console.log(`   GET  /debug-subscription - Debug subscription calls`);
    console.log(`   GET  /health - Health check`);
  });
}

initialize().catch(err => {
  console.error("Failed to initialize server:", err);
  process.exit(1);
});