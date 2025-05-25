const express = require("express");
const { ethers } = require("ethers"); // Import ethers at top level
const { create } = require("@web3-storage/w3up-client");
const hre = require("hardhat");
const axios = require("axios");
require("dotenv").config();

const app = express();
const port = 3002; // Agent server port

// Middleware to parse JSON bodies
app.use(express.json());

// Configuration - Add these to your .env file
const AGENT_PRIVATE_KEY = process.env.AGENT_PRIVATE_KEY;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const WEB3_STORAGE_EMAIL = process.env.WEB3_STORAGE_EMAIL;
const WEB3_STORAGE_SPACE_DID = process.env.WEB3_STORAGE_SPACE_DID;

// Validate environment variables
if (!AGENT_PRIVATE_KEY) {
  console.error("AGENT_PRIVATE_KEY not set in .env file");
  process.exit(1);
}

if (!OPENAI_API_KEY) {
  console.error("OPENAI_API_KEY not set in .env file");
  process.exit(1);
}

if (!WEB3_STORAGE_EMAIL || !WEB3_STORAGE_SPACE_DID) {
  console.error("WEB3_STORAGE_EMAIL or WEB3_STORAGE_SPACE_DID not set in .env file");
  process.exit(1);
}

// Task processing queue (in production, use Redis or similar)
const taskQueue = new Map();

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
  console.log("Agent server connected to network:", network.name, "Chain ID:", network.chainId);
  if (network.chainId !== 11155111n) {
    throw new Error(`Incorrect network! Expected Sepolia (chain ID 11155111), got ${network.name} (chain ID ${network.chainId})`);
  }
  return network;
}

// Function to call GPT-4o
async function callGPT4o(taskDescription) {
  try {
    console.log("Calling GPT-4o with task:", taskDescription);
    
    const response = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content:
              "You are a helpful AI assistant that completes tasks accurately and professionally. Provide detailed, well-structured responses. You must not provide any follow-up questions or clarifications. Just complete the task as described.",
          },
          {
            role: "user",
            content: taskDescription,
          },
        ],
        max_tokens: 500,
        temperature: 0.7,
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    const result = response.data.choices[0].message.content;
    console.log("GPT-4o response received, length:", result.length);
    return result;

  } catch (error) {
    console.error("Error calling GPT-4o:", error.response?.data || error.message);
    throw new Error(`GPT-4o API call failed: ${error.response?.data?.error?.message || error.message}`);
  }
}

// Function to upload to IPFS via Web3.Storage w3up-client
async function uploadToIPFS(content, filename = 'task_result.txt') {
  try {
    console.log("Uploading to IPFS via Web3.Storage w3up-client...");
    
    const web3Client = await create();
    await web3Client.login(WEB3_STORAGE_EMAIL);
    await web3Client.setCurrentSpace(WEB3_STORAGE_SPACE_DID);

    // Create a Blob from the content
    const taskBlob = new Blob([content], { type: 'text/plain' });
    // Create a File object with the specified filename
    const taskFile = new File([taskBlob], filename, { type: 'text/plain' });
    
    // Upload the file
    const cid = await web3Client.uploadFile(taskFile);
    
    console.log("Successfully uploaded to IPFS:", cid.toString());
    return cid.toString();

  } catch (error) {
    console.error("Error uploading to IPFS:", error.message);
    throw new Error(`IPFS upload failed: ${error.message}`);
  }
}

// Function to submit proof to blockchain
async function submitProofToBlockchain(taskUuid, proofCid, contractAddress) {
  try {
    console.log("Submitting proof to blockchain...");
    
    const provider = getSepoliaProvider();
    const agentWallet = new ethers.Wallet(AGENT_PRIVATE_KEY, provider);
    
    // Get contract ABI from Hardhat artifacts
    const TaskEscrowArtifact = await hre.artifacts.readArtifact("TaskEscrow");
    
    // Create contract instance
    const contract = new ethers.Contract(
      contractAddress,
      TaskEscrowArtifact.abi,
      agentWallet
    );

    const taskId = taskUuid;
    
    // Submit proof
    const tx = await contract.submitProof(taskId, proofCid, {
      gasLimit: 500000 // Adjust as needed
    });
    
    console.log("Proof submission transaction hash:", tx.hash);
    const receipt = await tx.wait();
    console.log("Proof submitted successfully in block:", receipt.blockNumber);
    
    return {
      transactionHash: tx.hash,
      blockNumber: receipt.blockNumber
    };

  } catch (error) {
    console.error("Error submitting proof to blockchain:", error.message);
    throw error;
  }
}

// Async task processor
async function processTask(taskUuid, contractAddress, taskDescription) {
  const taskInfo = {
    status: 'processing',
    startTime: new Date().toISOString(),
    taskUuid,
    contractAddress,
    taskDescription
  };
  
  taskQueue.set(taskUuid, taskInfo);
  
  try {
    console.log(`\n=== PROCESSING TASK ${taskUuid} ===`);
    
    // Step 1: Call GPT-4o
    taskInfo.status = 'calling_gpt4o';
    taskQueue.set(taskUuid, taskInfo);
    
    const gptResult = await callGPT4o(taskDescription);
    
    // Step 2: Upload to IPFS
    taskInfo.status = 'uploading_to_ipfs';
    taskInfo.gptResult = gptResult;
    taskQueue.set(taskUuid, taskInfo);
    
    const filename = `task_${taskUuid}_result.txt`;
    const proofCid = await uploadToIPFS(gptResult, filename);
    
    // Step 3: Submit proof to blockchain
    taskInfo.status = 'submitting_proof';
    taskInfo.proofCid = proofCid;
    taskQueue.set(taskUuid, taskInfo);
    
    const blockchainResult = await submitProofToBlockchain(taskUuid, proofCid, contractAddress);
    
    // Step 4: Mark as completed
    taskInfo.status = 'completed';
    taskInfo.completedTime = new Date().toISOString();
    taskInfo.transactionHash = blockchainResult.transactionHash;
    taskInfo.blockNumber = blockchainResult.blockNumber;
    taskQueue.set(taskUuid, taskInfo);
    
    console.log(`✅ TASK ${taskUuid} COMPLETED SUCCESSFULLY`);
    console.log(`   IPFS CID: ${proofCid}`);
    console.log(`   Transaction: ${blockchainResult.transactionHash}`);
    console.log(`   Block: ${blockchainResult.blockNumber}`);
    
  } catch (error) {
    console.error(`❌ TASK ${taskUuid} FAILED:`, error.message);
    
    taskInfo.status = 'failed';
    taskInfo.error = error.message;
    taskInfo.failedTime = new Date().toISOString();
    taskQueue.set(taskUuid, taskInfo);
  }
}

// Endpoint for agent to sign task
app.post("/sign-task", async (req, res) => {
  try {
    // Get Sepolia provider
    const provider = getSepoliaProvider();
    
    // Validate network
    await ensureSepoliaNetwork(provider);

    const { 
      task_uuid, 
      final_task_price, 
      client_address, 
      agent_wallet_address, 
      contract_address,
      task_description 
    } = req.body;

    // Validate input
    if (!task_uuid || !final_task_price || !client_address || !agent_wallet_address) {
      return res.status(400).json({
        error: "Missing required parameters: task_uuid, final_task_price, client_address, agent_wallet_address",
      });
    }

    if (!ethers.isAddress(client_address) || !ethers.isAddress(agent_wallet_address)) {
      return res.status(400).json({ error: "Invalid wallet addresses" });
    }

    let price;
    try {
      price = ethers.parseEther(final_task_price.toString());
    } catch (error) {
      return res.status(400).json({ error: "Invalid final_task_price format" });
    }

    // Initialize agent wallet
    const agentWallet = new ethers.Wallet(AGENT_PRIVATE_KEY, provider);
    const agentAddress = agentWallet.address;
    
    // Verify agent address matches the provided one
    if (agentAddress.toLowerCase() !== agent_wallet_address.toLowerCase()) {
      return res.status(400).json({ 
        error: "Agent wallet address mismatch",
        expected: agentAddress,
        provided: agent_wallet_address
      });
    }

    console.log("Agent address:", agentAddress);
    console.log("Signing task:", {
      task_uuid,
      price: ethers.formatEther(price),
      client_address,
      contract_address,
      task_description
    });

    // Create the message to sign (same format as expected by contract)
    const encoded = ethers.solidityPacked(
      ["bytes32", "uint256", "address"],
      [task_uuid, price, client_address]
    );
    const messageHash = ethers.keccak256(encoded);
    
    // Agent signs the message
    const signature = await agentWallet.signMessage(ethers.getBytes(messageHash));
    console.log("Agent signature generated:", signature);

    // Verify signature
    const recoveredAddress = ethers.verifyMessage(ethers.getBytes(messageHash), signature);
    if (recoveredAddress.toLowerCase() !== agentAddress.toLowerCase()) {
      return res.status(500).json({ error: "Agent signature verification failed" });
    }
    console.log("Agent signature verification: VALID");

    // Log the task acceptance
    console.log(`Agent ${agentAddress} accepted task ${task_uuid} for ${ethers.formatEther(price)} ETH from client ${client_address}`);

    // Respond with signature
    res.status(200).json({
      message: "Task signed successfully by agent",
      signature: signature,
      agent_address: agentAddress,
      task_uuid: task_uuid,
      task_price: ethers.formatEther(price),
      client_address: client_address,
      contract_address: contract_address,
      signed_at: new Date().toISOString(),
      task_description: task_description
    });

  } catch (error) {
    console.error("Agent signing error:", error.message);
    res.status(500).json({
      error: "Failed to sign task",
      details: error.message,
    });
  }
});

// NEW ENDPOINT: Begin task processing
app.post("/begin-task", async (req, res) => {
  try {
    const { task_uuid, contract_address, task_description } = req.body;

    // Validate input
    if (!task_uuid || !contract_address || !task_description) {
      return res.status(400).json({
        error: "Missing required parameters: task_uuid, contract_address, task_description"
      });
    }

    if (!ethers.isAddress(contract_address)) {
      return res.status(400).json({ error: "Invalid contract address" });
    }

    // Check if task is already being processed
    if (taskQueue.has(task_uuid)) {
      const existingTask = taskQueue.get(task_uuid);
      return res.status(409).json({
        error: "Task already being processed",
        current_status: existingTask.status,
        started_at: existingTask.startTime
      });
    }

    console.log(`📋 RECEIVED TASK REQUEST: ${task_uuid}`);
    console.log(`   Contract: ${contract_address}`);
    console.log(`   Description: ${task_description.substring(0, 100)}${task_description.length > 100 ? '...' : ''}`);

    // Start async processing (don't await)
    processTask(task_uuid, contract_address, task_description);

    // Return immediate success response
    res.status(200).json({
      message: "Task accepted and processing started",
      task_uuid: task_uuid,
      contract_address: contract_address,
      status: "processing",
      started_at: new Date().toISOString()
    });

  } catch (error) {
    console.error("Error starting task processing:", error.message);
    res.status(500).json({
      error: "Failed to start task processing",
      details: error.message
    });
  }
});

// Endpoint to check task status
app.get("/task-status/:task_uuid", (req, res) => {
  const { task_uuid } = req.params;
  
  if (!taskQueue.has(task_uuid)) {
    return res.status(404).json({
      error: "Task not found",
      task_uuid: task_uuid
    });
  }

  const taskInfo = taskQueue.get(task_uuid);
  res.status(200).json(taskInfo);
});

// Endpoint to get all task statuses
app.get("/tasks", (req, res) => {
  const tasks = Array.from(taskQueue.entries()).map(([uuid, info]) => ({
    task_uuid: uuid,
    ...info
  }));

  res.status(200).json({
    total_tasks: tasks.length,
    tasks: tasks
  });
});

// Endpoint to get agent info
app.get("/agent-info", async (req, res) => {
  try {
    const provider = getSepoliaProvider();
    const agentWallet = new ethers.Wallet(AGENT_PRIVATE_KEY, provider);
    const agentAddress = agentWallet.address;
    const balance = await provider.getBalance(agentAddress);

    res.status(200).json({
      agent_address: agentAddress,
      balance: ethers.formatEther(balance),
      network: "sepolia",
      openai_configured: !!OPENAI_API_KEY,
      web3_storage_configured: !!(WEB3_STORAGE_EMAIL && WEB3_STORAGE_SPACE_DID)
    });
  } catch (error) {
    console.error("Error getting agent info:", error.message);
    res.status(500).json({
      error: "Failed to get agent info",
      details: error.message,
    });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ 
    status: "Agent server is running",
    services: {
      blockchain: "connected",
      openai: OPENAI_API_KEY ? "configured" : "not configured",
      web3_storage: WEB3_STORAGE_EMAIL && WEB3_STORAGE_SPACE_DID ? "configured" : "not configured"
    }
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Agent server running at http://localhost:${port}`);
  console.log("=== CONFIGURATION STATUS ===");
  console.log("✅ Agent private key: configured");
  console.log(`${OPENAI_API_KEY ? '✅' : '❌'} OpenAI API: ${OPENAI_API_KEY ? 'configured' : 'not configured'}`);
  console.log(`${WEB3_STORAGE_EMAIL && WEB3_STORAGE_SPACE_DID ? '✅' : '❌'} Web3.Storage: ${WEB3_STORAGE_EMAIL && WEB3_STORAGE_SPACE_DID ? 'configured' : 'not configured'}`);
});