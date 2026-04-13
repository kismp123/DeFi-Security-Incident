# Arbitrary Call / Input Validation

Exploits where attackers supply arbitrary calldata or target addresses to hijack contract execution flow.

**Total incidents: 79**

---

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2022-03-19 | RedactedCartel | TransferFromApprovalBug | [2022-03-19_RedactedCartel_TransferFromApprovalBug.md](../2022/2022-03-19_RedactedCartel_TransferFromApprovalBug.md) |
| 2022-03-20 | LiFi | ArbitrarySwapCallExploit | [2022-03-20_LiFi_ArbitrarySwapCallExploit.md](../2022/2022-03-20_LiFi_ArbitrarySwapCallExploit.md) |
| 2022-03-28 | Auctus | ArbitraryCallTransferFrom | [2022-03-28_Auctus_ArbitraryCallTransferFrom.md](../2022/2022-03-28_Auctus_ArbitraryCallTransferFrom.md) |
| 2022-05-20 | Novo | TransferFromLPDrain | [2022-05-20_Novo_TransferFromLPDrain.md](../2022/2022-05-20_Novo_TransferFromLPDrain.md) |
| 2022-06-08 | Snood | TransferFromSyncDrain | [2022-06-08_Snood_TransferFromSyncDrain.md](../2022/2022-06-08_Snood_TransferFromSyncDrain.md) |
| 2022-09 | MEVbadc0de | DyDxArbitraryCall | [2022-09_MEVbadc0de_DyDxArbitraryCall.md](../2022/2022-09_MEVbadc0de_DyDxArbitraryCall.md) |
| 2022-10 | MEVa47b | BalancerArbitraryCall | [2022-10_MEVa47b_BalancerArbitraryCall.md](../2022/2022-10_MEVa47b_BalancerArbitraryCall.md) |
| 2022-10 | RabbyWallet | SwapRouterArbitraryCall | [2022-10_RabbyWallet_SwapRouterArbitraryCall.md](../2022/2022-10_RabbyWallet_SwapRouterArbitraryCall.md) |
| 2022-11 | BrahTOPG | ZapInArbitraryCall | [2022-11_BrahTOPG_ZapInArbitraryCall.md](../2022/2022-11_BrahTOPG_ZapInArbitraryCall.md) |
| 2022-11 | MEV | 0ad8 ArbitraryCallAllowanceDrain | [2022-11_MEV_0ad8_ArbitraryCallAllowanceDrain.md](../2022/2022-11_MEV_0ad8_ArbitraryCallAllowanceDrain.md) |
| 2022-11 | Polynomial | SwapDepositArbitraryCall | [2022-11_Polynomial_SwapDepositArbitraryCall.md](../2022/2022-11_Polynomial_SwapDepositArbitraryCall.md) |
| 2022-12 | Rubic | RouterCallNativeArbitraryCall | [2022-12_Rubic_RouterCallNativeArbitraryCall.md](../2022/2022-12_Rubic_RouterCallNativeArbitraryCall.md) |
| 2023-02-17 | Dexible | ArbitraryCall ETH | [2023-02-17_Dexible_ArbitraryCall_ETH.md](../2023/2023-02-17_Dexible_ArbitraryCall_ETH.md) |
| 2023-02-27 | RevertFinance | ArbitrarySwap | [2023-02-27_RevertFinance_ArbitrarySwap.md](../2023/2023-02-27_RevertFinance_ArbitrarySwap.md) |
| 2023-06-17 | Pawnfi | UntrustedInput ETH | [2023-06-17_Pawnfi_UntrustedInput_ETH.md](../2023/2023-06-17_Pawnfi_UntrustedInput_ETH.md) |
| 2023-06-xx | Contract0x7657 | ArbitraryTransferFrom | [2023-06-xx_Contract0x7657_ArbitraryTransferFrom.md](../2023/2023-06-xx_Contract0x7657_ArbitraryTransferFrom.md) |
| 2023-08-03 | MEVBot | 0xd61492 UnverifiedInput ARB | [2023-08-03_MEVBot_0xd61492_UnverifiedInput_ARB.md](../2023/2023-08-03_MEVBot_0xd61492_UnverifiedInput_ARB.md) |
| 2023-09-01 | DEXRouter | ArbitraryCall | [2023-09-01_DEXRouter_ArbitraryCall.md](../2023/2023-09-01_DEXRouter_ArbitraryCall.md) |
| 2023-10-05 | DePayRouter | CallInjection | [2023-10-05_DePayRouter_CallInjection.md](../2023/2023-10-05_DePayRouter_CallInjection.md) |
| 2023-10-24 | Maestro | ArbitraryCall ETH | [2023-10-24_Maestro_ArbitraryCall_ETH.md](../2023/2023-10-24_Maestro_ArbitraryCall_ETH.md) |
| 2023-12-16 | TransitFinance | CallInjection | [2023-12-16_TransitFinance_CallInjection.md](../2023/2023-12-16_TransitFinance_CallInjection.md) |
| 2023-12-20 | TransitFinance | UntrustedInput BSC | [2023-12-20_TransitFinance_UntrustedInput_BSC.md](../2023/2023-12-20_TransitFinance_UntrustedInput_BSC.md) |
| 2024-01-12 | SocketGateway | ArbitraryCall | [2024-01-12_SocketGateway_ArbitraryCall.md](../2024/2024-01-12_SocketGateway_ArbitraryCall.md) |
| 2024-01-16 | SocketGateway | ArbitraryCallRoute ETH | [2024-01-16_SocketGateway_ArbitraryCallRoute_ETH.md](../2024/2024-01-16_SocketGateway_ArbitraryCallRoute_ETH.md) |
| 2024-01-17 | BasketDAO | UnverifiedInput ETH | [2024-01-17_BasketDAO_UnverifiedInput_ETH.md](../2024/2024-01-17_BasketDAO_UnverifiedInput_ETH.md) |
| 2024-01-23 | Bmizapper | ArbitraryCall | [2024-01-23_Bmizapper_ArbitraryCall.md](../2024/2024-01-23_Bmizapper_ArbitraryCall.md) |
| 2024-02-15 | ParticleTrade | UnverifiedInput ETH | [2024-02-15_ParticleTrade_UnverifiedInput_ETH.md](../2024/2024-02-15_ParticleTrade_UnverifiedInput_ETH.md) |
| 2024-02-28 | Seneca | ArbitraryCall ETH | [2024-02-28_Seneca_ArbitraryCall_ETH.md](../2024/2024-02-28_Seneca_ArbitraryCall_ETH.md) |
| 2024-02-XX | Seneca | ArbitraryCall | [2024-02-XX_Seneca_ArbitraryCall.md](../2024/2024-02-XX_Seneca_ArbitraryCall.md) |
| 2024-03-08 | Unizen | ArbitraryCall Polygon | [2024-03-08_Unizen_ArbitraryCall_Polygon.md](../2024/2024-03-08_Unizen_ArbitraryCall_Polygon.md) |
| 2024-03-XX | ALP | ArbitrarySwapCall | [2024-03-XX_ALP_ArbitrarySwapCall.md](../2024/2024-03-XX_ALP_ArbitrarySwapCall.md) |
| 2024-03-XX | GHT | TransferFromSyncManipulation | [2024-03-XX_GHT_TransferFromSyncManipulation.md](../2024/2024-03-XX_GHT_TransferFromSyncManipulation.md) |
| 2024-03-XX | UnizenIO | ArbitraryCalldata | [2024-03-XX_UnizenIO_ArbitraryCalldata.md](../2024/2024-03-XX_UnizenIO_ArbitraryCalldata.md) |
| 2024-04-19 | HedgeyFinance | ArbitraryCall ETH | [2024-04-19_HedgeyFinance_ArbitraryCall_ETH.md](../2024/2024-04-19_HedgeyFinance_ArbitraryCall_ETH.md) |
| 2024-04-24 | YIEDL | UnverifiedInput BSC | [2024-04-24_YIEDL_UnverifiedInput_BSC.md](../2024/2024-04-24_YIEDL_UnverifiedInput_BSC.md) |
| 2024-04-XX | ChaingeFinance | ArbitraryCalldata | [2024-04-XX_ChaingeFinance_ArbitraryCalldata.md](../2024/2024-04-XX_ChaingeFinance_ArbitraryCalldata.md) |
| 2024-04-XX | YIEDL | SportVaultRedeemArbitrarySwap | [2024-04-XX_YIEDL_SportVaultRedeemArbitrarySwap.md](../2024/2024-04-XX_YIEDL_SportVaultRedeemArbitrarySwap.md) |
| 2024-06-XX | MineSTM | UpdateAllowanceSellExploit | [2024-06-XX_MineSTM_UpdateAllowanceSellExploit.md](../2024/2024-06-XX_MineSTM_UpdateAllowanceSellExploit.md) |
| 2024-06-XX | SteamSwap | UpdateAllowanceSellLarge | [2024-06-XX_SteamSwap_UpdateAllowanceSellLarge.md](../2024/2024-06-XX_SteamSwap_UpdateAllowanceSellLarge.md) |
| 2024-06-XX | YYS | UpdateAllowanceSellExploit | [2024-06-XX_YYS_UpdateAllowanceSellExploit.md](../2024/2024-06-XX_YYS_UpdateAllowanceSellExploit.md) |
| 2024-07-11 | DoughFinance | ArbitraryCalldata | [2024-07-11_DoughFinance_ArbitraryCalldata.md](../2024/2024-07-11_DoughFinance_ArbitraryCalldata.md) |
| 2024-07-15 | LW | TransferFromExploit | [2024-07-15_LW_TransferFromExploit.md](../2024/2024-07-15_LW_TransferFromExploit.md) |
| 2024-07-16 | LIFI | DiamondFacetArbitraryCall ETH | [2024-07-16_LIFI_DiamondFacetArbitraryCall_ETH.md](../2024/2024-07-16_LIFI_DiamondFacetArbitraryCall_ETH.md) |
| 2024-07-23 | Spectra | ArbitraryCall ETH | [2024-07-23_Spectra_ArbitraryCall_ETH.md](../2024/2024-07-23_Spectra_ArbitraryCall_ETH.md) |
| 2024-08-01 | Convergence | UnverifiedInput ETH | [2024-08-01_Convergence_UnverifiedInput_ETH.md](../2024/2024-08-01_Convergence_UnverifiedInput_ETH.md) |
| 2024-09-04 | Unveriifieda89f | SwapCallbackDrain | [2024-09-04_Unveriifieda89f_SwapCallbackDrain.md](../2024/2024-09-04_Unveriifieda89f_SwapCallbackDrain.md) |
| 2024-09-06 | Unverified5697 | TransferFromExploit | [2024-09-06_Unverified5697_TransferFromExploit.md](../2024/2024-09-06_Unverified5697_TransferFromExploit.md) |
| 2024-09-22 | Bankroll | UnverifiedInput BSC | [2024-09-22_Bankroll_UnverifiedInput_BSC.md](../2024/2024-09-22_Bankroll_UnverifiedInput_BSC.md) |
| 2024-09-26 | OnyxDAO | UnverifiedInput ETH | [2024-09-26_OnyxDAO_UnverifiedInput_ETH.md](../2024/2024-09-26_OnyxDAO_UnverifiedInput_ETH.md) |
| 2024-10-21 | MorphoBlue | ERC20TransferFromExploit | [2024-10-21_MorphoBlue_ERC20TransferFromExploit.md](../2024/2024-10-21_MorphoBlue_ERC20TransferFromExploit.md) |
| 2024-10-24 | Erc20transfer | ArbitraryTransferFrom | [2024-10-24_Erc20transfer_ArbitraryTransferFrom.md](../2024/2024-10-24_Erc20transfer_ArbitraryTransferFrom.md) |
| 2024-11-02 | CoW | SwapCallbackDrain | [2024-11-02_CoW_SwapCallbackDrain.md](../2024/2024-11-02_CoW_SwapCallbackDrain.md) |
| 2024-12-23 | MoonHacker | UnverifiedInput OP | [2024-12-23_MoonHacker_UnverifiedInput_OP.md](../2024/2024-12-23_MoonHacker_UnverifiedInput_OP.md) |
| 2025-06-25 | SiloFinance | ArbitraryCall Sonic | [2025-06-25_SiloFinance_ArbitraryCall_Sonic.md](../2025/2025-06-25_SiloFinance_ArbitraryCall_Sonic.md) |
| 2025-07-09 | GMX | UnverifiedInput ARB | [2025-07-09_GMX_UnverifiedInput_ARB.md](../2025/2025-07-09_GMX_UnverifiedInput_ARB.md) |
| 2025-08-07 | Bebop | dex ArbitraryTransferFrom | [2025-08-07_Bebop_dex_ArbitraryTransferFrom.md](../2025/2025-08-07_Bebop_dex_ArbitraryTransferFrom.md) |
| 2025-08-07 | SizeCredit | ArbitraryCall | [2025-08-07_SizeCredit_ArbitraryCall.md](../2025/2025-08-07_SizeCredit_ArbitraryCall.md) |
| 2026-01-25 | ApertureFinance | UnverifiedInput ETH | [2026-01-25_ApertureFinance_UnverifiedInput_ETH.md](../2026/2026-01-25_ApertureFinance_UnverifiedInput_ETH.md) |
| 2026-01-25 | SwapNet | ArbitraryCall ARB | [2026-01-25_SwapNet_ArbitraryCall_ARB.md](../2026/2026-01-25_SwapNet_ArbitraryCall_ARB.md) |
| 2026-01-30 | Gyro | ArbitraryCall ARB | [2026-01-30_Gyro_ArbitraryCall_ARB.md](../2026/2026-01-30_Gyro_ArbitraryCall_ARB.md) |
| 2022-10 | MulticallWithoutCheck | ArbitraryTransfer | [2022-10_MulticallWithoutCheck_ArbitraryTransfer.md](../2022/2022-10_MulticallWithoutCheck_ArbitraryTransfer.md) |
| 2023-11-12 | FiberRouter | CalldataInjection | [2023-11-12_FiberRouter_CalldataInjection.md](../2023/2023-11-12_FiberRouter_CalldataInjection.md) |
| 2024-02-XX | Paraswap | V3CallbackArbitraryTransfer | [2024-03-XX_Paraswap_V3CallbackArbitraryTransfer.md](../2024/2024-03-XX_Paraswap_V3CallbackArbitraryTransfer.md) |
| 2024-02-XX | Zoomer | ArbitrarySelector | [2024-02-XX_Zoomer_ArbitrarySelector.md](../2024/2024-02-XX_Zoomer_ArbitrarySelector.md) |
| 2024-07-13 | GAX | UnvalidatedLowLevelCall | [2024-07-13_GAX_UnvalidatedLowLevelCall.md](../2024/2024-07-13_GAX_UnvalidatedLowLevelCall.md) |
| 2024-11-18 | MainnetSettler | ArbitraryExecution | [2024-11-18_MainnetSettler_ArbitraryExecution.md](../2024/2024-11-18_MainnetSettler_ArbitraryExecution.md) |
| 2025-03-10 | OneInchFusion | CalldataCorruption | [2025-03-10_OneInchFusion_CalldataCorruption.md](../2025/2025-03-10_OneInchFusion_CalldataCorruption.md) |
| 2022-12 | BBOX | TransferHelperDrain | [2022-12_BBOX_TransferHelperDrain.md](../2022/2022-12_BBOX_TransferHelperDrain.md) |
| 2023-04-09 | SushiSwap | RouteProcessor ETH | [2023-04-09_SushiSwap_RouteProcessor_ETH.md](../2023/2023-04-09_SushiSwap_RouteProcessor_ETH.md) |
| 2024-04-XX | OpenLeverage2 | MarginTradeArbitraryDEX | [2024-04-XX_OpenLeverage2_MarginTradeArbitraryDEX.md](../2024/2024-04-XX_OpenLeverage2_MarginTradeArbitraryDEX.md) |
| 2024-04-XX | Rico | BankDiamondFlashArbitraryTransfer | [2024-04-XX_Rico_BankDiamondFlashArbitraryTransfer.md](../2024/2024-04-XX_Rico_BankDiamondFlashArbitraryTransfer.md) |
| 2024-05-XX | SCROLL | UniversalRouterExecute | [2024-05-XX_SCROLL_UniversalRouterExecute.md](../2024/2024-05-XX_SCROLL_UniversalRouterExecute.md) |
| 2024-06-XX | Bazaar | ExitPoolArbitraryHolder | [2024-06-XX_Bazaar_ExitPoolArbitraryHolder.md](../2024/2024-06-XX_Bazaar_ExitPoolArbitraryHolder.md) |
| 2024-07-19 | SpectraFinance | UniversalRouterBypass | [2024-07-19_SpectraFinance_UniversalRouterBypass.md](../2024/2024-07-19_SpectraFinance_UniversalRouterBypass.md) |
| 2024-07-26 | Spectra | Finance UniversalRouterBypass | [2024-07-26_Spectra_Finance_UniversalRouterBypass.md](../2024/2024-07-26_Spectra_Finance_UniversalRouterBypass.md) |
| 2024-09-05 | AIRBTC | CustomSelectorDrain | [2024-09-05_AIRBTC_CustomSelectorDrain.md](../2024/2024-09-05_AIRBTC_CustomSelectorDrain.md) |
| 2024-09-17 | MARA | EncodedCallExploit | [2024-09-17_MARA_EncodedCallExploit.md](../2024/2024-09-17_MARA_EncodedCallExploit.md) |
| 2025-07-22 | MulticallWithETH | ValueForwarding | [2025-07-22_MulticallWithETH_ValueForwarding.md](../2025/2025-07-22_MulticallWithETH_ValueForwarding.md) |
| 2024-05-19 | Mixed | Swap Router 라우터 취약점 | [2024-05-19_Mixed_Swap_Router_라우터_취약점.md](../2024/2024-05-19_Mixed_Swap_Router_라우터_취약점.md) |

---

[← Back to vulnerability index](./README.md)
