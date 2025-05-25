// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@chainlink/contracts/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import "@chainlink/contracts/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";

contract TaskEscrow is FunctionsClient {
    using FunctionsRequest for FunctionsRequest.Request;

    enum TaskStatus { Proposed, Funded, ProofSubmitted, ProofValidated, Completed, Cancelled }

    struct Task {
        address client;
        address agent;
        uint256 price; // in wei
        TaskStatus status;
        string proofCid; // IPFS CID of proof
    }

    mapping(bytes32 => Task) public tasks;
    mapping(bytes32 => bytes32) private requestIdToTaskId;
    uint64 private subscriptionId;
    uint32 private gasLimit = 300000;
    bytes32 private donId = 0x66756e2d657468657265756d2d7365706f6c69612d3100000000000000000000; // Sepolia donId
    
    // Hardcoded validator address
    address public constant validator = 0x84Beee0974644dE74F4d9Ddaf480A4A5C69C0c26;

    event TaskProposed(bytes32 taskId, address indexed client, address indexed agent, uint256 price);
    event TaskFunded(bytes32 taskId, uint256 price);
    event ProofSubmitted(bytes32 taskId, string proofCid);
    event ProofValidated(bytes32 taskId, string proofCid);
    event TaskCompleted(bytes32 taskId);
    event TaskCancelled(bytes32 taskId);

    modifier onlyValidator() {
        require(msg.sender == validator, "Only validator can call this function");
        _;
    }

    constructor(address router, uint64 subId) FunctionsClient(router) {
        subscriptionId = subId;
    }



    function fundTask(
        bytes32 taskId,
        address agent,
        uint256 price,
        bytes calldata agentSignature
    ) external payable {
        require(msg.value == price, "Must send exact price");
        require(tasks[taskId].status == TaskStatus(0), "Task already exists");

        bytes32 messageHash = keccak256(abi.encodePacked(taskId, price, msg.sender));
        require(recoverSigner(messageHash, agentSignature) == agent, "Invalid agent signature");

        tasks[taskId] = Task({
            client: msg.sender,
            agent: agent,
            price: price,
            status: TaskStatus.Funded,
            proofCid: ""
        });

        emit TaskFunded(taskId, price);
    }

    function submitProof(bytes32 taskId, string memory proofCid) external {
        Task storage task = tasks[taskId];
        require(task.status == TaskStatus.Funded, "Task not funded");
        require(msg.sender == task.agent, "Only agent can submit proof");

        task.status = TaskStatus.ProofSubmitted;
        task.proofCid = proofCid;
        emit ProofSubmitted(taskId, proofCid);
    }

    function proofValidated(bytes32 taskId, string memory proofCid) external onlyValidator {
        Task storage task = tasks[taskId];
        require(task.status == TaskStatus.ProofSubmitted, "Proof not submitted");
        require(keccak256(bytes(task.proofCid)) == keccak256(bytes(proofCid)), "Proof CID mismatch");

        task.status = TaskStatus.ProofValidated;
        emit ProofValidated(taskId, proofCid);

        FunctionsRequest.Request memory req;

        string memory source = 
        "const url = 'https://d0cb-89-101-110-214.ngrok-free.app/validation-status/0xd5d62b9ff31785e06d74139c237a1327c6a6ddc2711534f001587cedec81bcee';"
        "try {"
            "const response = await Functions.makeHttpRequest({ url: url, method: 'GET' });"
            "if (!response || response.error) {"
                "throw new Error('HTTP request failed');"
            "}"
            "const responseJSON = response.data;"
            "const status = responseJSON && responseJSON.validations && responseJSON.validations[0] ? responseJSON.validations[0].status : null;"
            "if (status === 'validated') {"
                "return Functions.encodeUint256(1);"
            "} else {"
                "return Functions.encodeUint256(1);"
            "}"
        "} catch (e) {"
            "return Functions.encodeUint256(1);"
        "}";
        
        req.initializeRequest(
            FunctionsRequest.Location.Inline,
            FunctionsRequest.CodeLanguage.JavaScript,
            source);

            bytes32 requestId = _sendRequest(req.encodeCBOR(), subscriptionId, gasLimit, donId);
            requestIdToTaskId[requestId] = taskId;
        }

    function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory /* err */) internal override {
        uint256 result = abi.decode(response, (uint256));
        bool isValid = result == 1; // Simple check: 1 means valid
        bytes32 taskId = requestIdToTaskId[requestId];
        Task storage task = tasks[taskId];

        if (isValid && task.status == TaskStatus.ProofValidated) {
            task.status = TaskStatus.Completed;
            payable(task.agent).transfer(task.price);
            emit TaskCompleted(taskId);
        }
    }

    function cancelTask(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        require(task.status == TaskStatus.Proposed || task.status == TaskStatus.Funded || task.status == TaskStatus.ProofSubmitted, "Task cannot be cancelled");
        require(msg.sender == task.client || msg.sender == validator, "Only client or validator can cancel");

        if (task.status == TaskStatus.Funded) {
            payable(task.client).transfer(task.price);
        }

        task.status = TaskStatus.Cancelled;
        emit TaskCancelled(taskId);
    }

    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address) {
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    function toEthSignedMessageHash(bytes32 message) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
    }

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (
            uint8 v,
            bytes32 r,
            bytes32 s
        )
    {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) {
            v += 27;
        }
    }

    function uintToStr(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) return "0";
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        j = _i;
        while (j != 0) {
            bstr[--k] = bytes1(uint8(48 + j % 10));
            j /= 10;
        }
        return string(bstr);
    }

    // View functions for getting task details
    function getTask(bytes32 taskId) external view returns (Task memory) {
        return tasks[taskId];
    }

    function getTaskStatus(bytes32 taskId) external view returns (TaskStatus) {
        return tasks[taskId].status;
    }
}