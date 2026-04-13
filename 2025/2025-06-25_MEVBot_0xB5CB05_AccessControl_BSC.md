# MEV Bot 0xB5CB05 — Access Control Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2025-06-25 |
| **Protocol** | MEV Bot 0xB5CB05 (BSC Arbitrage Bot) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$2,000,000 (aggregated across multiple Txs) |
| **Attacker** | [0xd5c6...122c](https://bscscan.com/address/0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c) |
| **Attack Contract** | [0x7c25...C57a](https://bscscan.com/address/0x7c2565b563e057d482be2bf77796047e5340c57a) |
| **Attack Tx** | [0x8c02...c73e](https://bscscan.com/tx/0x8c026c3939f7e2d0376d13e30859fa918a5a567348ca1329836df88bef30c73e) |
| **Vulnerable Contract** | [0xB5CB...c19c](https://bscscan.com/address/0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c) (bot fund storage) |
| **Victim Contract** | [0xB5CB...4a87](https://bscscan.com/address/0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87) (printMoney executor) |
| **Root Cause** | Missing caller authorization check in `printMoney()` — arbitrary external call allowed |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/unverified_b5cb_exp.sol) |
| **Incident Report** | [TenArmor Alert](https://x.com/TenArmorAlert/status/1937761064713941187) |

---

## 1. Vulnerability Overview

The two MEV bot contracts beginning with 0xB5CB05 are automated arbitrage bots operating on BSC. These bots internally contained an external call wrapper function named `printMoney()` (function selector `0x94655f2b`).

This function accepts an **array of contract addresses** and an **array of calldatas**, then sequentially executes a low-level `.call()` against each address. The issue is that this function contains **no access control logic whatsoever to verify `msg.sender`**.

The attacker exploited this flaw by:
1. Calling the `printMoney()` function on the vulnerable bot (`0xB5CB0555c4A...4a87`)
2. Encoding `transfer(attacker, balance)` calls for each token held by the other bot (`0xB5CB0555A1D...c19c`) as calldata arguments
3. The vulnerable bot performed delegated arbitrary calls on behalf of the owner, transferring funds to the attacker

This was a simple, extremely low-cost attack requiring no flash loan. A single contract deployment transaction (gas cost ~$0.13) drained approximately **$32,700 worth** of 7 tokens, and with multiple similar attack TXs, the total loss reached approximately **$2,000,000**.

---

## 2. Vulnerable Code Analysis

### 2.1 `printMoney()` — Missing Access Control (Core Vulnerability)

The bot's source code was not verified on-chain, but the following is reconstructed based on bytecode analysis and PoC behavior.

#### Vulnerable Code (❌)

```solidity
// ❌ Vulnerable code — printMoney() function
// Function selector: 0x94655f2b
// Vulnerability: no msg.sender check — anyone can make arbitrary external calls to arbitrary addresses with arbitrary calldata
function printMoney(
    address[] calldata targets,   // array of target contracts to call
    bytes[] calldata calldatas,   // array of calldatas to pass to each target
    bytes calldata extraData      // additional data (for internal routing)
) external {
    // ❌ No authorization check! Missing onlyOwner or onlyOperator
    for (uint256 i = 0; i < targets.length; i++) {
        (bool success,) = targets[i].call(calldatas[i]);
        // success is ignored or only checked for revert
    }
}
```

**Problem**: The MEV bot operator created this convenience function for managing multiple tokens in bulk internally but forgot to attach an `onlyOwner` modifier. Since arbitrary calldata can be injected from outside, an attacker can cause the bot to call the `transfer()` function of tokens it holds, under the bot's own identity.

#### Fixed Code (✅)

```solidity
// ✅ Fixed code — added owner-only access control
address private immutable owner;

modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

constructor() {
    owner = msg.sender;  // Set deployer as owner
}

// ✅ External calls blocked by adding onlyOwner modifier
function printMoney(
    address[] calldata targets,
    bytes[] calldata calldatas,
    bytes calldata extraData
) external onlyOwner {
    for (uint256 i = 0; i < targets.length; i++) {
        (bool success,) = targets[i].call(calldatas[i]);
        require(success, "Call failed");
    }
}
```

### 2.2 Stolen Token & Calldata Analysis

The attacker constructed the internal calldata for the `printMoney()` call as follows:

```
Internal calldata structure (repeated for each token):
  [0x0243f5a2] + [token address] + [transfer amount] + [recipient: attacker]
  [0xc1b1ef56] + [0x4848489f...484848] + [0] + [0]
```

- `0x0243f5a2`: Bot's internal transfer logic selector (effectively `transfer(token, amount, recipient)`)
- `0xc1b1ef56`: Additional cleanup function selector

On-chain Transfer events from the attack Tx (block 52052680):

| Token | Amount Stolen | Approximate USD |
|------|----------|----------|
| WBNB | 22.4917 BNB | ~$13,495 |
| ETH (BEP-20) | 1.5079 ETH | ~$3,770 |
| USDT | 5,713.6 USDT | ~$5,714 |
| TUSD | 4,253.6 TUSD | ~$4,254 |
| BTCB | 0.03202 BTCB | ~$1,921 |
| USDC | 2,028.1 USDC | ~$2,028 |
| FDUSD | 1,523.8 FDUSD | ~$1,524 |
| **Subtotal (this Tx)** | | **~$32,705** |

The loss from this single TX was ~$32K, and with similar attack TXs noted in the PoC comments executed repeatedly, the total loss reached **$2,000,000**.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No special preparation required (no flash loan)
- Attacker identified the `printMoney()` function selector (`0x94655f2b`) via on-chain bytecode analysis or transaction tracing
- Pre-encoded transfer calldata for each of the 7 tokens
- Attack executed as a single TX deploying attack contract `AttackerC` with all calldata hardcoded in the constructor

### 3.2 Execution Phase

```
1. Attacker EOA
   └─▶ Sends attack contract (AttackerC) deployment TX
        └─▶ constructor executes automatically

2. AttackerC constructor
   ├─ [Step 1] victim.call(printMoney_calldata_for_WBNB)
   │    └─▶ Victim bot executes owner_bot.transfer(22.49 WBNB → attacker)
   ├─ [Step 2] victim.call(printMoney_calldata_for_ETH)
   │    └─▶ Victim bot executes owner_bot.transfer(1.51 ETH → attacker)
   ├─ [Step 3] victim.call(printMoney_calldata_for_USDT)
   │    └─▶ Victim bot executes owner_bot.transfer(5,714 USDT → attacker)
   ├─ [Step 4] victim.call(printMoney_calldata_for_TUSD)
   │    └─▶ Victim bot executes owner_bot.transfer(4,254 TUSD → attacker)
   ├─ [Step 5] victim.call(printMoney_calldata_for_BTCB)
   │    └─▶ Victim bot executes owner_bot.transfer(0.032 BTCB → attacker)
   ├─ [Step 6] victim.call(printMoney_calldata_for_USDC)
   │    └─▶ Victim bot executes owner_bot.transfer(2,028 USDC → attacker)
   └─ [Step 7] victim.call(printMoney_calldata_for_FDUSD)
        └─▶ Victim bot executes owner_bot.transfer(1,524 FDUSD → attacker)
```

### 3.3 ASCII Box Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                     Attacker EOA                                  │
│          0xd5c6f3B71bCcEb2eF8332bd8225f5F39E56A122c              │
└─────────────────────────┬────────────────────────────────────────┘
                          │ 1. Contract deployment TX (gas cost $0.13)
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│                   AttackerC (attack contract)                     │
│          0x7C2565b563E057D482be2Bf77796047E5340C57a              │
│   7 repeated calls encoded in constructor()                      │
└─────────────────────────┬────────────────────────────────────────┘
                          │ 2. victim.call(printMoney(targets, calldatas))
                          │    ← No access control! (vulnerability)
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│                Victim MEV Bot (vulnerable contract)               │
│          0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87              │
│   printMoney() executes calldata passed as arguments as-is       │
│   ← No msg.sender check                                          │
└─────────────────────────┬────────────────────────────────────────┘
                          │ 3. token.transfer(attacker, balance)
                          │    (bot executes transfer under its own identity)
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│                Fund Storage Bot Contract                          │
│          0xB5CB0555A1D28C9DfdbC14017dae131d5c1cc19c              │
│   Held tokens: WBNB, ETH, USDT, TUSD, BTCB, USDC, FDUSD        │
└─────────────┬────────────────────────────────────────────────────┘
              │ 4. Token transfers (Transfer events × 7)
              ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Attacker EOA receives                         │
│          0xd5c6f3B71bCcEb2eF8332bd8225f5F39E56A122c              │
│   Gained: ~$32,705 (single Tx) / ~$2,000,000 total (multiple Tx)│
└──────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Single Tx profit**: ~$32,705
- **Total cumulative loss**: ~$2,000,000 (including similar attack TXs)
- **Attack cost**: ~$0.13 in gas (2,190,910 gas × 0.1 Gwei)
- **ROI**: Hundreds of millions times (relative to gas cost)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
// Source: DeFiHackLabs / unverified_b5cb_exp.sol

// @KeyInfo
// Total loss: ~$2M USD
// Attacker: 0xd5c6f3B71bCcEb2eF8332bd8225f5F39E56A122c
// Vulnerable contract: 0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c (fund storage)
// Victim contract: 0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87 (printMoney executor)
// Attack Tx: 0x8c026c3939f7e2d0376d13e30859fa918a5a567348ca1329836df88bef30c73e

address constant owner = 0xB5CB0555A1D28C9DfdbC14017dae131d5c1cc19c;   // fund storage bot
address constant victim = 0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87;  // printMoney vulnerable bot

// Attack contract — executes immediately in constructor upon deployment
contract AttackerC {
    constructor() {
        // [Step 1] Drain WBNB
        // printMoney() selector: 0x94655f2b
        // Internal calldata: transfer(WBNB, 22.49 BNB → attacker)
        (bool s1,) = victim.call(hex"94655f2b...{WBNB calldata}...");
        require(s1); // ← Check success (this itself is normal)

        // [Step 2] Drain ETH (BEP-20)
        (bool s2,) = victim.call(hex"94655f2b...{ETH calldata}...");
        require(s2);

        // [Step 3] Drain USDT
        (bool s3,) = victim.call(hex"94655f2b...{USDT calldata}...");
        require(s3);

        // [Step 4] Drain TUSD
        (bool s4,) = victim.call(hex"94655f2b...{TUSD calldata}...");
        require(s4);

        // [Step 5] Drain BTCB
        (bool s5,) = victim.call(hex"94655f2b...{BTCB calldata}...");
        require(s5);

        // [Step 6] Drain USDC
        (bool s6,) = victim.call(hex"94655f2b...{USDC calldata}...");
        require(s6);

        // [Step 7] Drain FDUSD — total ~$32K gained (this single Tx)
        (bool s7,) = victim.call(hex"94655f2b...{FDUSD calldata}...");
        require(s7);
    }
}
// Key insight: attacker completes 7 token drains with a single contract deployment
// No flash loan needed, no token approval needed, no upfront capital needed
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing access control on `printMoney()` | CRITICAL | CWE-284 |
| V-02 | Arbitrary External Call | CRITICAL | CWE-20 |
| V-03 | Unverified Contract Source Code | HIGH | CWE-693 |

### V-01: Missing Access Control on `printMoney()`

- **Description**: The bot's core execution function `printMoney()` (selector `0x94655f2b`) has no `msg.sender` validation. Despite being a powerful function that accepts arbitrary contract addresses and calldatas to execute low-level `.call()`, it can be called by anyone.
- **Impact**: An attacker can call this function to transfer all tokens held by the bot to an arbitrary address. Complete theft of the bot's funds is possible.
- **Attack Condition**: Instantly exploitable with knowledge of the vulnerable bot's address and the `printMoney()` selector. No special capital or prior authorization required.
- **Pattern Reference**: `03_access_control.md` — Pattern 1 (Missing Modifier)

### V-02: Arbitrary External Call

- **Description**: The `printMoney()` function executes the `targets` and `calldatas` passed as arguments without any validation. With no whitelist or calldata validation, an attacker can execute arbitrary token `transfer()` calls under the bot's identity.
- **Impact**: All tokens held by or approved to the bot can be transferred to an attacker-specified address.
- **Attack Condition**: Complete fund theft when combined with the missing access control in V-01.
- **Pattern Reference**: `03_access_control.md` — Pattern 7 (Arbitrary Call)

### V-03: Unverified Source Code

- **Description**: The vulnerable bot contract did not verify its source code on BscScan, making it difficult for external parties to audit the internal logic. This reduced the opportunity for security researchers to discover and report vulnerabilities proactively.
- **Impact**: No direct financial loss, but blocks the possibility of early vulnerability discovery and patching.
- **Attack Condition**: Not exploitable standalone. Exacerbates damage when combined with V-01 and V-02.

---

## 6. Remediation Recommendations

### Immediate Fix

```solidity
// ✅ Minimal patch that can be applied immediately

contract MEVBot {
    address private immutable owner;

    // Set owner at deployment
    constructor() {
        owner = msg.sender;
    }

    // ✅ Define onlyOwner modifier
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    // ✅ Apply onlyOwner to printMoney — most critical fix
    function printMoney(
        address[] calldata targets,
        bytes[] calldata calldatas,
        bytes calldata extraData
    ) external onlyOwner {  // ← modifier added
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call(calldatas[i]);
            require(success, "Call failed");
        }
    }

    // ✅ Apply same pattern to all other external fund movement functions
    function withdrawToken(address token, uint256 amount) external onlyOwner {
        IERC20(token).transfer(owner, amount);
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing access control | Apply `onlyOwner` or `onlyOperator` modifier to all external fund movement functions |
| V-02: Arbitrary external call | Introduce a contract address whitelist; maintain an allowed function selector list |
| V-03: Unverified source | Verify source code on BscScan — establish transparency and allow community audits |
| General | Introduce multi-sig or Timelock to reduce privilege concentration |
| General | Automation bots should hold only the minimum balance required for operations; excess funds should be moved to a separate cold wallet |

---

## 7. Lessons Learned

1. **MEV bots are smart contracts too**: Automated bots are not exempt from security review. Every contract holding significant funds requires strict access control.

2. **"Convenience functions" are the most dangerous**: The batch processing function (`printMoney()`) created for operator convenience became the primary attack vector. The more powerful a function, the stronger the access control required.

3. **Arbitrary external call patterns are always dangerous**: Arbitrary external calls in the form of `targets[i].call(calldatas[i])` must never be placed in public functions without a whitelist. An attacker can use them to perform any authorized action under the contract's identity.

4. **Simple attacks without flash loans can be more lethal**: This attack required zero capital. Over $32,000 was stolen for $0.13 in gas. Defending only against complex attacks is not sufficient.

5. **Source code verification is basic security hygiene**: Keeping contract source code private may appear to hide vulnerabilities, but in reality it blocks the opportunity for well-meaning security researchers to discover and raise alarms in advance. Security through obscurity does not work.

6. **Principle of Least Privilege**: Bot operation contracts should not hold more than the immediately required amount. Profits should be periodically moved to a separate, secure address.

---

## 8. On-Chain Verification

### 8.1 Basic Information

| Item | Value |
|------|-----|
| Block Number | 52,052,680 |
| Block Timestamp | 2025-06-25 (Unix: 0x685b71aa) |
| Attacker From | 0xd5c6f3B71bCcEb2eF8332bd8225f5F39E56A122c |
| Deployed Contract | 0x7C2565b563E057D482be2Bf77796047E5340C57a |
| Gas Used | 2,190,910 (43.8% of 5,000,000 limit) |
| Gas Price | 0.1 Gwei |
| Transaction Fee | 0.000219091 BNB (~$0.13) |
| Transaction Status | Success (status: 1) |

### 8.2 PoC vs On-Chain Transfer Event Comparison

| Token | Token Address | On-Chain Actual Transfer Amount | Converted (18 decimals) |
|------|----------|------------------|-----------------|
| WBNB | 0xbb4CdB9C...095c | 0x1382294b6a25c95b6 | 22.4917 WBNB |
| ETH (BEP-20) | 0x2170Ed08...33F8 | 0x14ed4fb12d0c1e2d | 1.5079 ETH |
| USDT | 0x55d39832...7955 | 0x135bc852b49b2cd8db4 | 5,713.63 USDT |
| TUSD | 0x40af3827...11c9 | 0xe696b963acf3b8ff37 | 4,253.61 TUSD |
| BTCB | 0x7130d2A1...ad9c | 0x71c00e14a47a0b | 0.03202 BTCB |
| USDC | 0x8AC76a51...80d | 0x6df1a2d94e17e00b0d | 2,028.11 USDC |
| FDUSD | 0xc5f0f7b6...409 | 0x529b36f9efe67f88b7 | 1,523.82 FDUSD |

`from` for all Transfer events: `0xB5CB0555A1D28C9DfdbC14017dae131d5c1cc19c` (fund storage bot)
`to` for all Transfer events: `0xd5c6f3B71bCcEb2eF8332bd8225f5F39E56A122c` (attacker)

### 8.3 On-Chain Event Log Order

```
logIndex 0x1a9  Transfer: WBNB      (22.49 BNB)   from bot → attacker
logIndex 0x1aa  Transfer: ETH BEP20 (1.508 ETH)   from bot → attacker
logIndex 0x1ab  Transfer: USDT      (5713.6 USDT)  from bot → attacker
logIndex 0x1ac  Transfer: TUSD      (4253.6 TUSD)  from bot → attacker
logIndex 0x1ad  Transfer: BTCB      (0.032 BTCB)   from bot → attacker
logIndex 0x1ae  Transfer: USDC      (2028.1 USDC)  from bot → attacker
logIndex 0x1af  Transfer: FDUSD     (1523.8 FDUSD) from bot → attacker
```

Total of 7 Transfer events; the order exactly matches the s1–s7 call sequence in the PoC.

### 8.4 Similar Attack Transactions

Similar attack TXs noted in the PoC comments:
- [0x7708...f44](https://bscscan.com/tx/0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44)
- [0xf902...6ff](https://bscscan.com/tx/0xf9025e317ce71bc8c055a511fccf0eb4eafd0b8c613da4d5a8e05e139966d6ff)

The total loss across these multiple attacks, including similar TXs, is assessed to be **$2,000,000**.

---

*Analysis date: 2026-04-11 | Pattern reference: `03_access_control.md` (Pattern 1, Pattern 7)*