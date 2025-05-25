const express = require("express");
const { JsonRpcProvider, Contract, Wallet } = require("ethers");
require("dotenv").config();
const { OpenAI } = require("openai");
const axios = require("axios");

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Initialize Express app
const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// Blockchain configuration
const SEPOLIA_RPC_URL =
  process.env.SEPOLIA_RPC_URL ||
  "https://sepolia.infura.io/v3/6a8d13960ee44d86b6de8a6327e317b1";
const VALIDATOR_PRIVATE_KEY = process.env.VALIDATOR_PRIVATE_KEY;
const IPFS_GATEWAY = process.env.IPFS_GATEWAY || "https://ipfs.io/ipfs/";

// Validate environment variables
if (!VALIDATOR_PRIVATE_KEY) {
  console.error("VALIDATOR_PRIVATE_KEY not set in .env file");
  process.exit(1);
}

// Initialize blockchain connections
const provider = new JsonRpcProvider(SEPOLIA_RPC_URL);
const wallet = new Wallet(VALIDATOR_PRIVATE_KEY, provider);

// Contract ABI
const contractABI = [
    "event ProofSubmitted(bytes32 taskId, string proofCid)",
    "event ProofValidated(bytes32 taskId, string proofCid)",
    "event TaskCompleted(bytes32 taskId)",
    "event TaskCancelled(bytes32 taskId)",
    "function proofValidated(bytes32 taskId, string memory proofCid) external",
    "function cancelTask(bytes32 taskId) external",
    "function getTask(bytes32 taskId) external view returns (tuple(address client, address agent, uint256 price, uint8 status, string proofCid))",
    "function getTaskStatus(bytes32 taskId) external view returns (uint8)",
    "function validator() external view returns (address)"
];

// Store active listeners and validation logs
const activeListeners = new Map();
const validationLogs = new Map();

// Validation rules configuration
const VALIDATION_CONFIG = {
  maxFileSize: 10 * 1024 * 1024,
  allowedContentTypes: [
    "application/json",
    "text/plain",
    "text/html",
    "text/markdown",
    "image/jpeg",
    "image/png",
    "image/gif",
  ],
  minDataLength: 10,
  requiredFields: [],
};

// Fetch file from IPFS with enhanced error handling
async function fetchFromIPFS(cid) {
  try {
    console.log(`📁 Fetching file from IPFS: ${cid}`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    const response = await fetch(`${IPFS_GATEWAY}${cid}`, {
      signal: controller.signal,
      headers: {
        "User-Agent": "TaskEscrow-Validator/1.0",
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const contentLength = response.headers.get("content-length");
    if (
      contentLength &&
      parseInt(contentLength) > VALIDATION_CONFIG.maxFileSize
    ) {
      throw new Error(`File too large: ${contentLength} bytes`);
    }

    const contentType = response.headers.get("content-type") || "text/plain";
    console.log(`📄 Content type: ${contentType}`);

    let data;
    if (contentType.includes("application/json")) {
      data = await response.json();
      console.log(
        `📋 JSON data:`,
        JSON.stringify(data, null, 2).substring(0, 500)
      );
    } else if (contentType.includes("image/")) {
      const buffer = await response.arrayBuffer();
      data = `Image data (${buffer.byteLength} bytes)`;
      console.log(`🖼️ Image data: ${data}`);
    } else {
      data = await response.text();
      console.log(`📄 Text data (first 200 chars):`, data.substring(0, 200));
    }

    return { success: true, data, contentType, size: contentLength };
  } catch (error) {
    console.error(`❌ Error fetching from IPFS:`, error.message);
    return { success: false, error: error.message };
  }
}

async function validateProofData(data, cid, actualTaskRequirements) {
  const validation = {
    isValid: false,
    reason: "",
    score: 0,
    checks: {},
  };

  try {
    const dataString =
      typeof data === "string" ? data : JSON.stringify(data, null, 2);
    const taskReqString =
      typeof actualTaskRequirements === "string"
        ? actualTaskRequirements
        : JSON.stringify(actualTaskRequirements, null, 2);

    const systemPrompt = `
You are an autonomous task validation agent.

Task requirements:
${taskReqString}

Submitted proof (from IPFS CID: ${cid}):
${dataString}

Score this proof from 0 to 1 based on how well it fulfills the task requirements.
Only return a single JSON object with the structure: { "score": number, "reason": string }
`;

    console.log("🧠 Calling OpenAI for proof validation...");
    const chatResponse = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [{ role: "system", content: systemPrompt }],
      temperature: 0.2,
    });

    const content = chatResponse.choices[0].message.content.trim();
    const result = JSON.parse(content);

    validation.score = result.score;
    validation.reason = result.reason;
    validation.isValid = validation.score >= 0.7;
    validation.checks.gptScore = result.score;

    console.log(`✅ OpenAI GPT validation result:`, validation);

    return validation;
  } catch (err) {
    console.error("❌ GPT validation error:", err.message);
    validation.reason = `GPT validation error: ${err.message}`;
    return validation;
  }
}

// Update task status in client server
async function updateTaskStatus(taskId, state, proofCid, verifierNotes = "") {
  try {
    console.log(`📤 Updating task status for task ${taskId} to ${state} with proof CID ${proofCid}...`);
    const response = await axios.post("http://localhost:3001/update-task-status", {
      task_uuid: taskId,
      state: state,
      proof_cid: proofCid,
      verifier_notes: verifierNotes,
    });
    console.log(`✅ Task status updated:`, response.data);
    return true;
  } catch (error) {
    console.error(`❌ Failed to update task status:`, error.message);
    return false;
  }
}

// Enhanced proof submission handler with better debugging
async function handleProofSubmission(
  taskId,
  proofCid,
  event,
  contractWithSigner,
  contractAddress
) {
  const validationId = `${taskId}-${proofCid}`;

  console.log(`\n📋 Processing proof submission:`);
  console.log(`  Task ID: ${taskId}`);
  console.log(`  Proof CID: ${proofCid}`);
  console.log(`  Block: ${event.blockNumber}`);
  console.log(`  Contract: ${contractAddress}`);

  // Store validation start
  validationLogs.set(validationId, {
    taskId,
    proofCid,
    startTime: new Date(),
    status: "processing",
    event: {
      blockNumber: event.blockNumber,
      transactionHash: event.transactionHash,
      contractAddress: contractAddress,
    },
  });

  try {
    const contractReadOnly = new Contract(
      contractAddress,
      contractABI,
      provider
    );

    // ✅ CRITICAL: Verify validator address matches
    console.log(`🔍 Checking validator authorization...`);
    const walletAddress = await wallet.getAddress();
    console.log(`🔑 Our wallet address: ${walletAddress}`);

    try {
      const contractValidator = await contractReadOnly.validator();
      console.log(`🏛️ Contract validator address: ${contractValidator}`);

      if (walletAddress.toLowerCase() !== contractValidator.toLowerCase()) {
        const error = `❌ VALIDATOR MISMATCH! Wallet: ${walletAddress}, Contract expects: ${contractValidator}`;
        console.error(error);
        validationLogs.get(validationId).status = "auth_failed";
        validationLogs.get(validationId).error = error;
        return;
      }
      console.log(`✅ Validator address matches!`);
    } catch (validatorCheckError) {
      console.error(
        `❌ Failed to check validator address:`,
        validatorCheckError.message
      );
      // Continue anyway, but log the issue
    }

    // Check task status and details
    console.log(`🔍 Checking task status...`);
    const taskStatus = await contractReadOnly.getTaskStatus(taskId);
    const task = await contractReadOnly.getTask(taskId);

    console.log(
      `📊 Task Status: ${taskStatus} (0=Proposed, 1=Funded, 2=ProofSubmitted, 3=ProofValidated, 4=Completed, 5=Cancelled)`
    );
    console.log(`📋 Task Details:`, {
      client: task[0],
      agent: task[1],
      price: task[2].toString(),
      status: task[3],
      storedCid: task[4],
    });

    // Validation checks
    if (taskStatus !== 2n) {
      const error = `Task status is ${taskStatus}, expected 2 (ProofSubmitted)`;
      console.error(`❌ ${error}`);
      validationLogs.get(validationId).status = "wrong_status";
      validationLogs.get(validationId).error = error;
      return;
    }

    if (task[4] !== proofCid) {
      const error = `CID mismatch! Contract: ${task[4]}, Event: ${proofCid}`;
      console.error(`❌ ${error}`);
      validationLogs.get(validationId).status = "cid_mismatch";
      validationLogs.get(validationId).error = error;
      return;
    }

    // Fetch and validate proof
    console.log(`📥 Fetching proof from IPFS...`);
    const ipfsResult = await fetchFromIPFS(proofCid);
    if (!ipfsResult.success) {
      const error = `Failed to fetch IPFS file: ${ipfsResult.error}`;
      console.error(`❌ ${error}`);
      validationLogs.get(validationId).status = "ipfs_failed";
      validationLogs.get(validationId).error = error;
      return;
    }

    console.log(`📥 Fetching task requirements from Platform...`);
    const taskRequirementsResult = await fetch(
      `http://localhost:3001/get-task/${taskId}`,
      {
        method: "GET",
      }
    );

    if (!taskRequirementsResult.ok) {
      const error = `Failed to fetch task requirements: HTTP ${taskRequirementsResult.status}`;
      console.error(`❌ ${error}`);
      validationLogs.get(validationId).status = "requirements_failed";
      validationLogs.get(validationId).error = error;
      return;
    }

    const parsedTaskRequirements = await taskRequirementsResult.json();
    const actualTaskRequirements =
      parsedTaskRequirements.task_validation_requirements;
    console.log(`📋 Task validation requirements:`, actualTaskRequirements);

    console.log(`🔍 Validating proof data...`);
    const validationResult = await validateProofData(
      ipfsResult.data,
      proofCid,
      actualTaskRequirements
    );

    // Store validation details
    validationLogs.get(validationId).validation = validationResult;
    validationLogs.get(validationId).ipfsData = {
      contentType: ipfsResult.contentType,
      size: ipfsResult.size,
      dataPreview:
        typeof ipfsResult.data === "string"
          ? ipfsResult.data.substring(0, 100)
          : JSON.stringify(ipfsResult.data).substring(0, 100),
    };

    if (!validationResult.isValid) {
      const error = `Proof validation failed: ${validationResult.reason}, attempting to cancel task`;
      console.error(`❌ ${error}`);
      validationLogs.get(validationId).status = "validation_rejected";
      validationLogs.get(validationId).error = error;

      // Attempt to cancel the task on the blockchain
      try {
        console.log(`🔗 Preparing to call cancelTask for task ${taskId}...`);

        // Check current nonce
        const nonce = await wallet.getNonce();
        console.log(`🔐 Current nonce: ${nonce}`);

        // Check balance
        const balance = await provider.getBalance(walletAddress);
        console.log(
          `💰 Wallet balance: ${balance.toString()} wei (${(
            Number(balance) / 1e18
          ).toFixed(4)} ETH)`
        );

        // Estimate gas
        console.log(`⛽ Estimating gas for cancelTask...`);
        let gasEstimate;
        try {
          gasEstimate = await contractWithSigner.cancelTask.estimateGas(taskId);
          console.log(`⛽ Estimated gas: ${gasEstimate.toString()}`);
        } catch (gasError) {
          console.error(`❌ Gas estimation failed for cancelTask:`, gasError);
          validationLogs.get(validationId).status = "cancel_tx_failed";
          validationLogs.get(
            validationId
          ).error = `Cancel transaction gas estimation failed: ${gasError.message}`;
          return;
        }

        // Get current gas price
        const feeData = await provider.getFeeData();
        console.log(`⛽ Gas price info:`, {
          gasPrice: feeData.gasPrice?.toString(),
          maxFeePerGas: feeData.maxFeePerGas?.toString(),
          maxPriorityFeePerGas: feeData.maxPriorityFeePerGas?.toString(),
        });

        // Execute cancelTask transaction
        console.log(`📤 Sending cancelTask transaction...`);
        const tx = await contractWithSigner.cancelTask(taskId, {
          gasLimit: gasEstimate + 50000n, // Add buffer
          nonce: nonce,
        });

        console.log(`📤 Transaction sent: ${tx.hash}`);
        console.log(`⏳ Waiting for confirmation...`);

        const receipt = await tx.wait();
        console.log(`✅ Transaction confirmed in block ${receipt.blockNumber}`);
        console.log(`⛽ Gas used: ${receipt.gasUsed.toString()}`);
        console.log(
          `💰 Transaction fee: ${(
            (Number(receipt.gasUsed) *
              Number(receipt.gasPrice || feeData.gasPrice || 0n)) /
            1e18
          ).toFixed(6)} ETH`
        );

        // Update validation log
        validationLogs.get(validationId).status = "task_cancelled";
        validationLogs.get(validationId).transaction = {
          hash: tx.hash,
          blockNumber: receipt.blockNumber,
          gasUsed: receipt.gasUsed.toString(),
          nonce: nonce,
        };
        validationLogs.get(validationId).endTime = new Date();

        console.log(
          `✅ Successfully cancelled task ${taskId} due to invalid proof`
        );

        // Update task status in client server
        await updateTaskStatus(taskId, "cancelled", proofCid, validationResult.reason);
      } catch (txError) {
        console.error(`❌ Cancel transaction failed:`, txError);

        // Enhanced error logging
        const errorDetails = {
          message: txError.message,
          code: txError.code,
          data: txError.data,
          transaction: txError.transaction,
          receipt: txError.receipt,
        };

        console.error(
          `❌ Full error details:`,
          JSON.stringify(errorDetails, null, 2)
        );

        validationLogs.get(validationId).status = "cancel_tx_failed";
        validationLogs.get(
          validationId
        ).error = `Cancel transaction failed: ${txError.message}`;
        validationLogs.get(validationId).errorDetails = errorDetails;
      }

      return;
    }

    // ✅ ENHANCED: Execute validation transaction with better debugging
    console.log(`🔗 Preparing to call proofValidated for task ${taskId}...`);

    try {
      // Check current nonce
      const nonce = await wallet.getNonce();
      console.log(`🔐 Current nonce: ${nonce}`);

      // Check balance
      const balance = await provider.getBalance(walletAddress);
      console.log(
        `💰 Wallet balance: ${balance.toString()} wei (${(
          Number(balance) / 1e18
        ).toFixed(4)} ETH)`
      );

      // Estimate gas first
      console.log(`⛽ Estimating gas...`);
      let gasEstimate;
      try {
        gasEstimate = await contractWithSigner.proofValidated.estimateGas(
          taskId,
          proofCid
        );
        console.log(`⛽ Estimated gas: ${gasEstimate.toString()}`);
      } catch (gasError) {
        console.error(`❌ Gas estimation failed:`, gasError);
        if (gasError.data) {
          console.error(`❌ Error data: ${gasError.data}`);
        }
        throw gasError;
      }

      // Get current gas price
      const feeData = await provider.getFeeData();
      console.log(`⛽ Gas price info:`, {
        gasPrice: feeData.gasPrice?.toString(),
        maxFeePerGas: feeData.maxFeePerGas?.toString(),
        maxPriorityFeePerGas: feeData.maxPriorityFeePerGas?.toString(),
      });

      // Execute transaction
      console.log(`📤 Sending transaction...`);
      const tx = await contractWithSigner.proofValidated(taskId, proofCid, {
        gasLimit: gasEstimate + 50000n, // Add buffer
        nonce: nonce,
      });

      console.log(`📤 Transaction sent: ${tx.hash}`);
      console.log(`⏳ Waiting for confirmation...`);

      const receipt = await tx.wait();
      console.log(`✅ Transaction confirmed in block ${receipt.blockNumber}`);
      console.log(`⛽ Gas used: ${receipt.gasUsed.toString()}`);
      console.log(
        `💰 Transaction fee: ${(
          (Number(receipt.gasUsed) *
            Number(receipt.gasPrice || feeData.gasPrice || 0n)) /
          1e18
        ).toFixed(6)} ETH`
      );

      // Update validation log
      validationLogs.get(validationId).status = "validated";
      validationLogs.get(validationId).transaction = {
        hash: tx.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed.toString(),
        nonce: nonce,
      };
      validationLogs.get(validationId).endTime = new Date();

      console.log(
        `✅ Successfully processed and validated proof for task ${taskId}`
      );

      // Update task status in client server
      await updateTaskStatus(taskId, "verified", proofCid, validationResult.reason);
    } catch (txError) {
      console.error(`❌ Transaction failed:`, txError);

      // Enhanced error logging
      const errorDetails = {
        message: txError.message,
        code: txError.code,
        data: txError.data,
        transaction: txError.transaction,
        receipt: txError.receipt,
      };

      console.error(
        `❌ Full error details:`,
        JSON.stringify(errorDetails, null, 2)
      );

      validationLogs.get(validationId).status = "tx_failed";
      validationLogs.get(
        validationId
      ).error = `Transaction failed: ${txError.message}`;
      validationLogs.get(validationId).errorDetails = errorDetails;
      return;
    }
  } catch (error) {
    const errorMsg = `Error processing proof for task ${taskId}: ${error.message}`;
    console.error(`❌ ${errorMsg}`);
    validationLogs.get(validationId).status = "error";
    validationLogs.get(validationId).error = errorMsg;
    validationLogs.get(validationId).endTime = new Date();
  }
}

// Stop listener for a specific contract
function stopListener(contractAddress) {
  if (activeListeners.has(contractAddress)) {
    const { contractReadOnly } = activeListeners.get(contractAddress);
    contractReadOnly.removeAllListeners();
    activeListeners.delete(contractAddress);
    console.log(`🛑 Stopped listener for contract ${contractAddress}`);
    return true;
  }
  return false;
}

// API endpoint to start listener
app.get("/start-listener", async (req, res) => {
  const contractAddress = req.query.contractAddress;

  if (!contractAddress || !/^0x[a-fA-F0-9]{40}$/.test(contractAddress)) {
    return res
      .status(400)
      .json({ error: "Invalid or missing contractAddress" });
  }

  try {
    // Check if listener already exists
    if (activeListeners.has(contractAddress)) {
      return res.status(200).json({
        message: `Listener already running for contract ${contractAddress}`,
        status: "already_running",
      });
    }

    // Create contract instances
    const contractReadOnly = new Contract(
      contractAddress,
      contractABI,
      provider
    );
    const contractWithSigner = new Contract(
      contractAddress,
      contractABI,
      wallet
    );

    // Enhanced contract validation
    try {
      console.log(`🔍 Validating contract at ${contractAddress}...`);

      // Check if contract exists
      const code = await provider.getCode(contractAddress);
      if (code === "0x") {
        throw new Error("No contract found at this address");
      }

      // Try to call a view function to validate ABI
      await contractReadOnly.getTaskStatus(
        "0x0000000000000000000000000000000000000000000000000000000000000000"
      );
      console.log(`✅ Contract ABI validated`);

      // Check validator address
      const walletAddress = await wallet.getAddress();
      try {
        const contractValidator = await contractReadOnly.validator();
        console.log(`🔍 Contract validator: ${contractValidator}`);
        console.log(`🔑 Our wallet: ${walletAddress}`);

        if (walletAddress.toLowerCase() !== contractValidator.toLowerCase()) {
          console.warn(
            `⚠️ WARNING: Validator mismatch! Contract expects: ${contractValidator}, but using: ${walletAddress}`
          );
          return res.status(400).json({
            error: "Validator address mismatch",
            expected: contractValidator,
            actual: walletAddress,
          });
        }
      } catch (validatorError) {
        console.warn(
          `⚠️ Could not check validator address:`,
          validatorError.message
        );
      }
    } catch (error) {
      if (error.message.includes("call revert exception")) {
        console.log(
          `✅ Contract validation passed (expected revert for empty task)`
        );
      } else {
        throw new Error(`Contract validation failed: ${error.message}`);
      }
    }

    // Start listener
    console.log(
      `🔮 Starting proof submission listener for contract ${contractAddress}...`
    );
    const network = await provider.getNetwork();
    console.log(
      `🌐 Connected to network: ${network.name} (chainId: ${network.chainId})`
    );

    const walletAddress = await wallet.getAddress();
    const balance = await provider.getBalance(walletAddress);
    console.log(`🔑 Validator wallet: ${walletAddress}`);
    console.log(
      `💰 Wallet balance: ${balance.toString()} wei (${(
        Number(balance) / 1e18
      ).toFixed(4)} ETH)`
    );

    const latestBlock = await provider.getBlockNumber();
    console.log(`📦 Latest block: ${latestBlock}`);

    // Set up event listener
    contractReadOnly.on("ProofSubmitted", (taskId, proofCid, event) =>
      handleProofSubmission(
        taskId,
        proofCid,
        event,
        contractWithSigner,
        contractAddress
      )
    );

    // Store listener
    activeListeners.set(contractAddress, {
      contractReadOnly,
      contractWithSigner,
      startTime: new Date(),
      walletAddress,
    });

    // Check for recent events
    console.log(`🔍 Checking for recent ProofSubmitted events...`);
    const currentBlock = await provider.getBlockNumber();
    const fromBlock = Math.max(0, currentBlock - 5000); // Last 5000 blocks

    const events = await contractReadOnly.queryFilter(
      "ProofSubmitted",
      fromBlock,
      currentBlock
    );
    console.log(`📊 Found ${events.length} recent ProofSubmitted events`);

    if (events.length > 0) {
      // Process the latest event
      const latestEvent = events.reduce((latest, current) => {
        if (current.blockNumber > latest.blockNumber) return current;
        if (
          current.blockNumber === latest.blockNumber &&
          current.logIndex > latest.logIndex
        )
          return current;
        return latest;
      });

      console.log(
        `🔄 Processing latest event from block ${latestEvent.blockNumber}`
      );
      await handleProofSubmission(
        latestEvent.args.taskId,
        latestEvent.args.proofCid,
        latestEvent,
        contractWithSigner,
        contractAddress
      );
    }

    res.status(200).json({
      message: `Listener started for contract ${contractAddress}`,
      status: "started",
      network: network.name,
      validator: walletAddress,
      balance: balance.toString(),
      recentEvents: events.length,
    });
  } catch (error) {
    console.error(`❌ Failed to start listener for ${contractAddress}:`, error);
    res.status(500).json({
      error: "Failed to start listener",
      details: error.message,
    });
  }
});

// API endpoint to stop listener
app.post("/stop-listener", (req, res) => {
  const { contractAddress } = req.body;

  if (!contractAddress || !/^0x[a-fA-F0-9]{40}$/.test(contractAddress)) {
    return res
      .status(400)
      .json({ error: "Invalid or missing contractAddress" });
  }

  const stopped = stopListener(contractAddress);
  if (stopped) {
    res
      .status(200)
      .json({ message: `Listener stopped for contract ${contractAddress}` });
  } else {
    res
      .status(404)
      .json({
        error: `No active listener found for contract ${contractAddress}`,
      });
  }
});

// API endpoint to get validation status
app.get("/validation-status/:taskId", (req, res) => {
  const taskId = req.params.taskId;
  const validations = Array.from(validationLogs.entries())
    .filter(([key, value]) => value.taskId === taskId)
    .map(([key, value]) => ({ validationId: key, ...value }));

  if (validations.length === 0) {
    return res
      .status(404)
      .json({ error: "No validation records found for this task" });
  }

  res.status(200).json({ taskId, validations });
});

// API endpoint to get all active listeners
app.get("/listeners", (req, res) => {
  const listeners = Array.from(activeListeners.entries()).map(
    ([address, data]) => ({
      contractAddress: address,
      startTime: data.startTime,
      validatorAddress: data.walletAddress,
    })
  );

  res.status(200).json({
    activeListeners: listeners.length,
    listeners,
  });
});

// Enhanced health check endpoint
app.get("/health", async (req, res) => {
  try {
    const network = await provider.getNetwork();
    const blockNumber = await provider.getBlockNumber();
    const walletAddress = await wallet.getAddress();
    const balance = await provider.getBalance(walletAddress);

    res.status(200).json({
      status: "Validation server is running",
      network: network.name,
      chainId: network.chainId.toString(),
      blockNumber,
      validator: walletAddress,
      balance: balance.toString(),
      balanceETH: (Number(balance) / 1e18).toFixed(4),
      activeListeners: activeListeners.size,
      totalValidations: validationLogs.size,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      error: error.message,
    });
  }
});

// New API endpoint to check validator authorization for a specific contract
app.get("/check-validator/:contractAddress", async (req, res) => {
  const contractAddress = req.params.contractAddress;

  if (!contractAddress || !/^0x[a-fA-F0-9]{40}$/.test(contractAddress)) {
    return res.status(400).json({ error: "Invalid contract address" });
  }

  try {
    const contractReadOnly = new Contract(
      contractAddress,
      contractABI,
      provider
    );
    const walletAddress = await wallet.getAddress();

    const contractValidator = await contractReadOnly.validator();
    const isAuthorized =
      walletAddress.toLowerCase() === contractValidator.toLowerCase();

    res.status(200).json({
      contractAddress,
      contractValidator,
      ourWallet: walletAddress,
      isAuthorized,
      status: isAuthorized ? "authorized" : "unauthorized",
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to check validator authorization",
      details: error.message,
    });
  }
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n🛑 Shutting down validation server...");
  activeListeners.forEach((_, contractAddress) =>
    stopListener(contractAddress)
  );
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log("\n🛑 Shutting down validation server...");
  activeListeners.forEach((_, contractAddress) =>
    stopListener(contractAddress)
  );
  process.exit(0);
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Validation server running on http://localhost:${port}`);
  console.log(`🔧 Configured for network: ${SEPOLIA_RPC_URL}`);
  console.log(`🔍 IPFS Gateway: ${IPFS_GATEWAY}`);
  console.log(`📋 Available endpoints:`);
  console.log(`  GET  /health - Server health check`);
  console.log(
    `  GET  /start-listener?contractAddress=0x... - Start listening to contract`
  );
  console.log(`  POST /stop-listener - Stop listening to contract`);
  console.log(`  GET  /listeners - List active listeners`);
  console.log(`  GET  /validation-status/:taskId - Get validation status`);
  console.log(
    `  GET  /check-validator/:contractAddress - Check validator authorization`
  );
});