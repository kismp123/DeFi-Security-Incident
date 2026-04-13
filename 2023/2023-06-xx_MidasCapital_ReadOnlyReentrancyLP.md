# Midas Capital XYZ Exploit — Read-Only Reentrancy via LP Oracle Manipulation

## Metadata
| Field | Value |
|---|---|
| Date | 2023-06 |
| Project | Midas Capital XYZ |
| Chain | BSC |
| Loss | ~$600,000 |
| Attacker | Address unconfirmed |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | fsAMM_HAY_BUSD: 0xF8527Dc5611B589CbB365aCACaac0d1DC70b25cB |
| Block | 29,185,768 |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow — oracle read during reentrancy) |
| Vulnerability Type | Read-Only Reentrancy via Flash Swap LP Token Mint/Redeem Oracle Manipulation |

## Summary
Midas Capital on BSC used LP token prices from a live oracle for collateral valuation. An attacker used nested flash loans (PancakeSwap V2 + Algebra V3) to manipulate HAY/BUSDT LP token balances during a mint/redeem cycle, causing the oracle to report inflated collateral values. The attacker then borrowed HAY, BUSDT, and other tokens against the inflated LP collateral.

## Vulnerability Details
- **CWE-841**: The Midas Capital oracle read LP token prices from current pool balances during the attacker's flash swap callback — a window when the pool state was temporarily manipulated. The oracle did not guard against reentrancy via `VaultReentrancyLib` or similar, allowing the inflated price to be used for collateral valuation within the same transaction.

### On-Chain Source Code

Source: Bytecode decompiled

```solidity
// File: MidasCapital_decompiled.sol
contract MidasCapital {  // ❌

    // Selector: 0x5c60da1b
    function implementation() external view returns (address) {}

}
```

## Attack Flow (from testExploit())
```solidity
// 1. deal(HAY, 220_000e18) + deal(BUSDT, 23_000e18)
// 2. ankrBNB_ANKRV2.swap(...)  → PancakeV2 flash swap callback
// 3. pancakeCall():
//    ankrBNB_ANKRV3.flash(...)  → Algebra V3 flash callback
// 4. algebraFlashCallback():
//    a. HAY_BUSDT_Vault.deposit(HAY+BUSDT) → receive LP tokens
//    b. fsAMM_HAY_BUSD.mint(lpTokens) → enter Midas market
//    c. Unitroller.enterMarkets([fsAMM_HAY_BUSD])
//    d. oracle reads manipulated pool balance → inflated collateral
//    e. fsAMM.borrow(HAY, maxAmount)
//    f. fsAMM.borrow(BUSDT, maxAmount)
//    g. Exit position, repay flash loans
```

## Interfaces from PoC
```solidity
interface ICErc20Delegate {
    function mint(uint256 mintAmount) external returns (uint256);
    function redeem(uint256 redeemTokens) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
}

interface ICointroller {
    function enterMarkets(address[] calldata cTokens) external returns (uint256[] memory);
}

interface ISimplePriceOracle {
    function getUnderlyingPrice(address cToken) external view returns (uint256);
}
```

## Key Addresses
| Label | Address |
|---|---|
| fsAMM_HAY_BUSD (Vulnerable) | 0xF8527Dc5611B589CbB365aCACaac0d1DC70b25cB |
| Oracle | 0xB641c21124546e1c979b4C1EbF13aB00D43Ee8eA |
| HAY | 0x0782b6d8c4551B9760e74c0545a9bCD90bdc41E5 |
| BUSDT | 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56 |
| WBNB | 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c |
| ANKR | 0xf307910A4c7bbc79691fD374889b36d8531B08e3 |
| ankrBNB | 0x52F24a5e03aee338Da5fd9Df68D2b6FAe1178827 |
| HAY_BUSDT_Vault | 0x02706A482fc9f6B20238157B56763391a45bE60E |
| Unitroller | 0x1851e32F34565cb95754310b031C5a2Fc0a8a905 |
| ankrBNB_ANKRV2 | 0x8028AC1195B6469de22929C4f329f96B06d65F25 |
| ankrBNB_ANKRV3 | 0xC8Cbf9b12552c0B85fc368AA530cc31E00526E2F |

## Root Cause
The Midas Capital LP price oracle read live pool balances without a reentrancy guard, allowing the attacker to manipulate LP token prices during a flash swap callback and borrow against the inflated collateral within the same transaction.

## Fix
```solidity
// Apply Balancer VaultReentrancyLib pattern to LP oracle:
import {VaultReentrancyLib} from "@balancer-labs/v2-pool-utils/contracts/lib/VaultReentrancyLib.sol";

function getUnderlyingPrice(address cToken) external view returns (uint256) {
    // Prevent read during active flash swap:
    _ensureNotInFlashContext();
    return _computeLPPrice(cToken);
}

function _ensureNotInFlashContext() internal view {
    // Check if any flash loan is currently active in the calling context
    require(!_flashActive, "Oracle: reentrancy detected");
}
```

## References
- BSC block 29,185,768
- fsAMM_HAY_BUSD: 0xF8527Dc5611B589CbB365aCACaac0d1DC70b25cB