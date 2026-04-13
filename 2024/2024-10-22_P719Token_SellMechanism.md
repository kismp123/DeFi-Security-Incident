# P719 Token — Sell Mechanism Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-10-22 |
| **Protocol** | P719 Token |
| **Chain** | BSC |
| **Loss** | ~312,000 USD (547 BNB) |
| **Attacker** | [0xfeb19ae8](https://bscscan.com/address/0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6) |
| **Attack Tx** | [0x9afcac8e](https://bscscan.com/tx/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3) |
| **Vulnerable Contract** | [0x6beee2b5](https://bscscan.com/token/0x6beee2b57b064eac5f432fc19009e3e78734eabc) |
| **Root Cause** | When P719 transfer() sends tokens to itself, fee tokens are mishandled, causing price distortion |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/P719Token_exp.sol) |

---
## 1. Vulnerability Overview

The `transfer()` function of the P719 token calculates a BNB amount via a Uniswap-like swap mechanism when tokens are sent to the contract itself (the P719 contract address). A bug in this process causes fee tokens to be mishandled, artificially inflating the token price. The attacker exploited this mechanism repeatedly through multiple buy/sell contracts.

## 2. Vulnerable Code Analysis

```solidity
// ❌ P719 transfer: abnormal behavior when sending to self
// (unverified contract, behavior analyzed from observation)
function transfer(address to, uint256 amount) public returns (bool) {
    if (to == address(this)) {
        // ❌ Tokens sent to P719 → BNB amount calculated internally
        // After burn, fee tokens are mishandled → price increases
        uint256 bnbOut = _calculateSellAmount(amount);
        _burn(msg.sender, amount);
        // ❌ Fee token handling error → LP price distortion
        _handleFeeTokens(bnbOut);
        payable(msg.sender).transfer(bnbOut);
    }
    // ...
}

// ✅ Fix: block self-transfers, use explicit sell() function
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: P719Token_decompiled.sol
contract P719Token {
    function transfer(address p0, uint256 p1) external {}  // ❌ vulnerable
```

## 3. Attack Flow

```
Attacker
  │
  ├─[1]─▶ Deploy MyToken (attacker-owned token)
  │
  ├─[2]─▶ Create MyToken/WBNB LP (0.001 BNB)
  │
  ├─[3]─▶ AttackerC.setup(myToken) and attack()
  │         Deploy multiple Buy/Sell contracts
  │
  ├─[4]─▶ PancakeV3 flash loan: borrow large amount of WBNB
  │
  ├─[5]─▶ Repeated purchases:
  │         Buy P719 → P719.transfer(P719, amount)
  │         └─ ❌ Fee token handling error → price distortion
  │
  ├─[6]─▶ Dump large amount of P719 at inflated price
  │
  ├─[7]─▶ Remove MyToken/WBNB LP
  │
  └─[8]─▶ ~547 BNB profit
```

## 4. PoC Code

```solidity
function testPoC() public {
    vm.startPrank(attacker);
    AttackerC attackerC = new AttackerC();

    // Deploy attacker token + LP
    myToken = new MyToken();
    myToken.approve(PancakeRouter, type(uint256).max);
    IFS(PancakeRouter).addLiquidityETH{value: 0.001 ether}(
        address(myToken), 100 ether, 100 ether, 0.001 ether, attacker, block.timestamp
    );

    // Set up and execute attack contract
    attackerC.setup(address(myToken));
    attackerC.attack();  // manipulates P719 price internally

    // Remove LP
    address factory = IFS(PancakeRouter).factory();
    // removeLiquidity...
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Vulnerability |
| **Attack Vector** | Self-transfer fee handling error |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Block self-transfers**: `require(to != address(this))`
2. **Explicit sell()**: Handle burn + BNB exchange through a dedicated `sell()` function
3. **Isolate fee handling**: Separate fee token processing from transfer logic
4. **Price invariant check**: Verify LP price remains within acceptable bounds before and after each transfer

## 7. Lessons Learned

- Tokens with built-in buy/sell mechanisms must clearly separate that logic from standard transfers.
- Excessive side effects in `transfer()` introduce unexpected economic vulnerabilities.
- The 547 BNB loss could have been prevented with a single line blocking self-transfers.