# SELLC Exploit — StakingRewards sell() Drains Reserves via Fake Referral Chain

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | SELLC / QIQI |
| Chain | BSC |
| Loss | ~$95,000 |
| Attacker | 0xa3aa817587556c023e78b2285d381c68cee17069 |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | StakingRewards: 0x274b3e185c9c8f4ddEF79cb9A8dC0D94f73A7675 |
| Block | 28,092,673 |
| CWE | CWE-284 (Improper Access Control — sell() no caller validation) |
| Vulnerability Type | StakingRewards.sell() Unrestricted Token Extraction via Fake LP |

## Summary
SELLC's `StakingRewards` contract exposed an `addLiquidity()` and `sell()` function without caller validation. The attacker created a malicious token (SHITCOIN), added it as fake liquidity, then called `sell()` 23 times to repeatedly drain the `SellQILP` reserve of SELLC tokens. Flash loan was used via PancakeSwap to fund the initial liquidity and cover round-trips.

## Vulnerability Details
- **CWE-284**: `StakingRewards.sell(address token, address token1, uint256 amount)` transferred tokens from its reserves to the caller without verifying that the caller had a legitimate staking position or that the token pair was authorized. Any address could supply a fake token pair and drain real reserves.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: StakingRewards.sol
    function stakedOfTimeSum(address,address,uint)external view returns (uint);  // ❌

// ...

    function stakedSum(address,address)external view returns (uint);  // ❌

// ...

    function myReward(address)external view returns (address);  // ❌

// ...

    function upaddress(address)external view returns (address);  // ❌

// ...

    function users(address,address)external view returns (uint,uint,uint);  // ❌
```

## Attack Flow (from testExploit())
```solidity
// init():
// 1. Swap WBNB → SELLC, create SELLC-QIQI LP
// 2. Deploy malicious token (SHITCOIN) with 100 supply
// 3. StakingRewards.addLiquidity(address(SHITCOIN), address(SELLC), amount)
//    → attacker's fake pair registered in staking contract
// 4. Create custom SHITCOIN/QIQI pair on custom factory
//
// init2():
// 5. Mint unlimited SHITCOIN
// 6. Repeatedly call StakingRewards.sell(SHITCOIN, SELLC, amount)
//    → no validation: drains SellQILP SELLC reserves each call
//
// process(23):
// 7. Execute 23 iterations of init2() drain
// 8. SELLC → WBNB via Router
```

## Interfaces from PoC
```solidity
interface IStakingRewards {
    function addLiquidity(address _token, address token1, uint256 amount1) external;
    function sell(address token, address token1, uint256 amount) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| StakingRewards (Vulnerable) | 0x274b3e185c9c8f4ddEF79cb9A8dC0D94f73A7675 |
| SELLC Token | 0xa645995e9801F2ca6e2361eDF4c2A138362BADe4 |
| QIQI Token | 0x8121D345b16469F38Bd3b82EE2a547f6Be54f9C9 |
| SellQILP | 0x4cd4Bf5079Fc09d6989B4b5B42b113377AD8d565 |
| Custom Factory | 0x2c37655f8D942f2411d9d85a5FE580C156305070 |
| Custom Router | 0xBDDFA43dbBfb5120738C922fa0212ef1E4a0850B |
| Attacker | 0xa3aa817587556c023e78b2285d381c68cee17069 |
| Attack Contract | 0x9a366027e6be5ae8441c9f54455e1d6c41f12e3c |

## Root Cause
`sell()` transferred tokens from protocol reserves without validating that the caller had a legitimate registered position or that the token pair was from an authorized factory. Any address with any token could register fake liquidity and drain real reserves.

## Fix
```solidity
// Whitelist approved token pairs and validate caller stake:
mapping(bytes32 => bool) public approvedPairs;
mapping(address => mapping(bytes32 => uint256)) public stakedAmount;

function sell(address token, address token1, uint256 amount) external {
    bytes32 pairKey = keccak256(abi.encodePacked(token, token1));
    require(approvedPairs[pairKey], "Pair not approved");
    require(stakedAmount[msg.sender][pairKey] >= amount, "Insufficient stake");
    stakedAmount[msg.sender][pairKey] -= amount;
    IERC20(token1).safeTransfer(msg.sender, amount);
}
```

## References
- BSC block 28,092,673
- StakingRewards: 0x274b3e185c9c8f4ddEF79cb9A8dC0D94f73A7675