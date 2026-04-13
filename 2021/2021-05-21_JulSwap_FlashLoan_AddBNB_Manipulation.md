# JulSwap — Flash Swap addBNB() Protocol Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2021-05-21 |
| **Protocol** | JulSwap |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$1,500,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 7,785,586) |
| **Vulnerable Contract** | [0x32dffc3fe8e3ef3571bf8a72c0d0015c5373f41d](https://bscscan.com/address/0x32dffc3fe8e3ef3571bf8a72c0d0015c5373f41d) (JulSwap) |
| **Root Cause** | `addBNB()` references the current contract BNB balance (spot) when calculating JUL mint amount, allowing mint manipulation via large BNB inflows |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/JulSwap_exp.sol) |

---
## 1. Vulnerability Overview

JulSwap is a decentralized exchange on BSC. JulProtocolV2 provides an `addBNB()` function that allows users to deposit BNB and receive JUL tokens. The attacker flash-swapped 70 trillion JUL tokens from a BSCSwap pair, converted them to BNB via the router, then called `JulProtocolV2.addBNB()` to manipulate the protocol's internal price/state. This allowed the attacker to receive an excessive amount of JUL tokens, sell them back to BNB, and repay the flash swap.

---
## 2. Vulnerable Code Analysis

### 2.1 addBNB() — Using Current BNB Balance for Internal Price Calculation

```solidity
// ❌ JulProtocolV2
// When addBNB() processes flash-loan-scale BNB inflows,
// the internal JUL/BNB ratio calculation becomes distorted

interface IJulProtocolV2 {
    // Deposit BNB and receive JUL
    // Internal reserve-based calculation is manipulated by large BNB inflows
    function addBNB() external payable;
}

// Vulnerability: addBNB() internally calculates JUL mint amount
// using the current contract BNB balance → manipulable by injecting
// large amounts of BNB via flash loan
function addBNB() external payable {
    uint256 bnbAmount = msg.value;
    // ❌ JUL mint amount calculated based on current BNB balance (spot-based)
    uint256 julOut = calculateJulOut(bnbAmount, address(this).balance);
    // julOut becomes abnormally large with flash loan BNB
    JUL.mint(msg.sender, julOut);
}
```

**Fixed Code**:
```solidity
// ✅ Use time-weighted reserve + limit inflow per single transaction
uint256 public constant MAX_BNB_PER_TX = 100 ether;

function addBNB() external payable nonReentrant {
    require(msg.value <= MAX_BNB_PER_TX, "JulProtocol: too much BNB per tx");

    // Use checkpoint reserve instead of current balance
    uint256 julOut = calculateJulOutTWAP(msg.value);
    JUL.mint(msg.sender, julOut);

    emit BNBAdded(msg.sender, msg.value, julOut);
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**JulSwap_decompiled.sol** — Entry point:
```solidity
// ❌ Root Cause: addBNB() references the current contract BNB balance (spot) when calculating JUL mint amount — mint manipulation possible via large BNB inflows
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Flash swap 70 trillion JUL from BSCSwap pair    │
│ BSCswapPair.swap(70_000_000_000_000e18, 0, this, data)  │
│ BSCswapCall() callback executed                         │
└─────────────────────┬───────────────────────────────────┘
                      │ BSCswapCall() callback
┌─────────────────────▼───────────────────────────────────┐
│ Step 2: Convert borrowed JUL → BNB                      │
│ router.swapExactTokensForETH(julAmount, 0, [JUL, BNB])  │
│ ~515 BNB obtained                                       │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 3: JulProtocolV2.addBNB{value: 515 ether}()        │
│ @ 0x32dffc3fe8e3ef3571bf8a72c0d0015c5373f41d            │
│ → Manipulate JUL mint amount via large BNB inflow       │
│ → Receive excess JUL                                    │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 4: Sell received JUL back to BNB                   │
│ router.swapExactTokensForETH(julBalance, 0, [JUL, BNB]) │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 5: BNB → Buy back JUL (for flash swap repayment)   │
│ Repay flash swap principal + fee → Realize profit       │
└─────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// BSCswapCall() — Flash swap callback (BSC fork block 7,785,586)
function BSCswapCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // 1. Convert borrowed JUL → BNB (obtain 515 BNB)
    // router.swapExactTokensForETH(
    //     JUL.balanceOf(address(this)), 0, [JUL, WBNB], address(this), deadline
    // )

    // 2. Call JulProtocolV2.addBNB() — over-mint JUL with 515 BNB
    // JulProtocolV2(0x32dffc3fe8e3ef3571bf8a72c0d0015c5373f41d)
    //     .addBNB{value: 515 ether}()

    // 3. Sell received JUL back to BNB
    // router.swapExactTokensForETH(julBalance, 0, [JUL, WBNB], ...)

    // 4. BNB → Buy back JUL (prepare for flash swap repayment)
    // router.swapExactETHForTokens{value: repayBNB}(0, [WBNB, JUL], pair, deadline)

    // 5. Repay flash swap JUL
    // JUL.transfer(bscswapPair, repayAmount)
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `addBNB()` references the current contract BNB balance (spot) when calculating JUL mint amount — mint manipulation possible via large BNB inflows | CRITICAL | CWE-829 |
| V-02 | No BNB inflow cap per single transaction (contributing factor: flash swap provides large-scale funds) | MEDIUM | CWE-20 |

> **Root Cause**: `addBNB()` internally calculates the JUL mint amount using spot price based on current balance. Flash swap is merely the funding mechanism; switching to checkpoint reserve or TWAP is the essential fix.

---
## 6. Remediation Recommendations

```solidity
// ✅ Cap addBNB() per-transaction limit
// ✅ Use TWAP or checkpoint reserve for JUL mint calculation

uint256 public constant MAX_BNB_PER_TX = 10 ether; // max 10 BNB/tx
uint256 public lastReserveUpdate;
uint256 public reserveBNB;

function addBNB() external payable nonReentrant {
    require(msg.value > 0 && msg.value <= MAX_BNB_PER_TX, "JulProtocol: invalid amount");

    // Use reserve from last update (checkpoint, not spot)
    uint256 effectiveBNB = reserveBNB;
    uint256 julOut = (msg.value * JUL_PER_BNB_BASE) / effectiveBNB;

    // Update reserve
    reserveBNB = address(this).balance;
    lastReserveUpdate = block.timestamp;

    JUL.mint(msg.sender, julOut);
}
```

---
## 7. Lessons Learned

- **Spot price-based minting inside `addBNB()` is the root cause.** Switching to checkpoint reserve or TWAP is the essential fix, more critical than simply capping inflow amounts.
- **Flash swap is the attack funding mechanism, not the vulnerability itself.** Eliminating the spot price dependency makes the attack impossible even without a flash swap.
- **When a protocol's own token has shallow liquidity, prices are easily distorted by large swaps.** Mint calculations must not reference such prices.