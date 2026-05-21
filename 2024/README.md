# 2024 DeFi Security Incidents

Business logic flaws on BSC and Ethereum dominated. Arbitrary call vulnerabilities and unverified input exploits became more common as attackers targeted protocol-specific logic rather than generic patterns.

**Total incidents: 234**

---

## Top Vulnerability Types

| Type | Count |
|------|-------|
| BusinessLogic BSC | 6 |
| AccessControl BSC | 5 |
| UnverifiedInput ETH | 4 |
| AccessControl ETH | 4 |
| ArbitraryCall | 3 |
| BusinessLogic ETH | 3 |
| FlashLoanPriceManipulation | 3 |
| PriceManipulation | 3 |
| ArbitraryCall ETH | 3 |
| PriceDependency BSC | 3 |

---

## Incident List

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2024-01-02 | RadiantCapital | EmptyMarketRounding ARB | [2024-01-02_RadiantCapital_EmptyMarketRounding_ARB.md](./2024-01-02_RadiantCapital_EmptyMarketRounding_ARB.md) |
| 2024-01-04 | GammaStrategies | PriceManipulation ARB | [2024-01-04_GammaStrategies_PriceManipulation_ARB.md](./2024-01-04_GammaStrategies_PriceManipulation_ARB.md) |
| 2024-01-05 | Loot | GovernanceAttack ETH | [2024-01-05_Loot_GovernanceAttack_ETH.md](./2024-01-05_Loot_GovernanceAttack_ETH.md) |
| 2024-01-12 | WiseLending | BusinessLogic ETH | [2024-01-12_WiseLending_BusinessLogic_ETH.md](./2024-01-12_WiseLending_BusinessLogic_ETH.md) |
| 2024-01-14 | WiseLending03 | SharePriceInflation | [2024-01-14_WiseLending03_SharePriceInflation.md](./2024-01-14_WiseLending03_SharePriceInflation.md) |
| 2024-01-15 | LQDX | MissingAccessControl | [2024-01-15_LQDX_MissingAccessControl.md](./2024-01-15_LQDX_MissingAccessControl.md) |
| 2024-01-16 | CitadelFinance | PriceOracleManipulation | [2024-01-16_CitadelFinance_PriceOracleManipulation.md](./2024-01-16_CitadelFinance_PriceOracleManipulation.md) |
| 2024-01-16 | SocketGateway | ArbitraryCallRoute ETH | [2024-01-16_SocketGateway_ArbitraryCallRoute_ETH.md](./2024-01-16_SocketGateway_ArbitraryCallRoute_ETH.md) |
| 2024-01-17 | BasketDAO | UnverifiedInput ETH | [2024-01-17_BasketDAO_UnverifiedInput_ETH.md](./2024-01-17_BasketDAO_UnverifiedInput_ETH.md) |
| 2024-01-18 | XSIJ | FlashLoanPriceManipulation | [2024-01-18_XSIJ_FlashLoanPriceManipulation.md](./2024-01-18_XSIJ_FlashLoanPriceManipulation.md) |
| 2024-01-19 | MIC | FlashLoanLPFeeExploit | [2024-01-19_MIC_FlashLoanLPFeeExploit.md](./2024-01-19_MIC_FlashLoanLPFeeExploit.md) |
| 2024-01-22 | DAOSoulMate | AccessControl ETH | [2024-01-22_DAOSoulMate_AccessControl_ETH.md](./2024-01-22_DAOSoulMate_AccessControl_ETH.md) |
| 2024-01-25 | NBLGAME | Reentrancy OP | [2024-01-25_NBLGAME_Reentrancy_OP.md](./2024-01-25_NBLGAME_Reentrancy_OP.md) |
| 2024-01-25 | Shell Protocol | MEV Sandwich Attack | [2024-01-25_ShellProtocol_MEVSandwich.md](./2024-01-25_ShellProtocol_MEVSandwich.md) |
| 2024-01-26 | Freedom | FlashLoanPriceManipulation | [2024-01-26_Freedom_FlashLoanPriceManipulation.md](./2024-01-26_Freedom_FlashLoanPriceManipulation.md) |
| 2024-01-27 | PeapodsFinance | FlashLoanBondAccumulation | [2024-01-27_PeapodsFinance_FlashLoanBondAccumulation.md](./2024-01-27_PeapodsFinance_FlashLoanBondAccumulation.md) |
| 2024-01-28 | BarleyFinance | Reentrancy ETH | [2024-01-28_BarleyFinance_Reentrancy_ETH.md](./2024-01-28_BarleyFinance_Reentrancy_ETH.md) |
| 2024-01-30 | MIMSpell2 | PrecisionLossManipulation | [2024-01-30_MIMSpell2_PrecisionLossManipulation.md](./2024-01-30_MIMSpell2_PrecisionLossManipulation.md) |
| 2024-01-31 | CheckDotProtocol | AccessControl BSC | [2024-01-31_CheckDotProtocol_AccessControl_BSC.md](./2024-01-31_CheckDotProtocol_AccessControl_BSC.md) |
| 2024-01-31 | ChrisLarsen | PrivateKeyCompromise XRP | [2024-01-31_ChrisLarsen_PrivateKeyCompromise_XRP.md](./2024-01-31_ChrisLarsen_PrivateKeyCompromise_XRP.md) |
| 2024-02-01 | AffineDeFi | FlashLoanCallback | [2024-02-01_AffineDeFi_FlashLoanCallback.md](./2024-02-01_AffineDeFi_FlashLoanCallback.md) |
| 2024-02-06 | ADC | BusinessLogicFlaw | [2024-02-06_ADC_BusinessLogicFlaw.md](./2024-02-06_ADC_BusinessLogicFlaw.md) |
| 2024-02-09 | DN404 | ProxyInitExploit | [2024-02-09_DN404_ProxyInitExploit.md](./2024-02-09_DN404_ProxyInitExploit.md) |
| 2024-02-09 | PlayDapp | UnauthorizedMint ETH | [2024-02-09_PlayDapp_UnauthorizedMint_ETH.md](./2024-02-09_PlayDapp_UnauthorizedMint_ETH.md) |
| 2024-02-12 | BurnsDefi | FlashLoanBurnToHolder | [2024-02-12_BurnsDefi_FlashLoanBurnToHolder.md](./2024-02-12_BurnsDefi_FlashLoanBurnToHolder.md) |
| 2024-02-13 | CompoundUni | PriceManipulation | [2024-02-13_CompoundUni_PriceManipulation.md](./2024-02-13_CompoundUni_PriceManipulation.md) |
| 2024-02-14 | Babyloogn | AirdropApprovalExploit | [2024-02-14_Babyloogn_AirdropApprovalExploit.md](./2024-02-14_Babyloogn_AirdropApprovalExploit.md) |
| 2024-02-15 | ParticleTrade | UnverifiedInput ETH | [2024-02-15_ParticleTrade_UnverifiedInput_ETH.md](./2024-02-15_ParticleTrade_UnverifiedInput_ETH.md) |
| 2024-02-16 | FixedFloat | HotWalletDrain Multi | [2024-02-16_FixedFloat_HotWalletDrain_Multi.md](./2024-02-16_FixedFloat_HotWalletDrain_Multi.md) |
| 2024-02-21 | DeezNutz404 | AccountingError ETH | [2024-02-21_DeezNutz404_AccountingError_ETH.md](./2024-02-21_DeezNutz404_AccountingError_ETH.md) |
| 2024-02-22 | BlueberryProtocol | PriceOracleRounding ETH | [2024-02-22_BlueberryProtocol_PriceOracleRounding_ETH.md](./2024-02-22_BlueberryProtocol_PriceOracleRounding_ETH.md) |
| 2024-02-28 | Seneca | ArbitraryCall ETH | [2024-02-28_Seneca_ArbitraryCall_ETH.md](./2024-02-28_Seneca_ArbitraryCall_ETH.md) |
| 2024-02-XX | DualPools | FlashLoanOracleManipulation | [2024-02-XX_DualPools_FlashLoanOracleManipulation.md](./2024-02-XX_DualPools_FlashLoanOracleManipulation.md) |
| 2024-02-XX | EGGX | NFTClaimMisvalidation | [2024-02-XX_EGGX_NFTClaimMisvalidation.md](./2024-02-XX_EGGX_NFTClaimMisvalidation.md) |
| 2024-02-XX | GAIN | FlashLoanSkimSync | [2024-02-XX_GAIN_FlashLoanSkimSync.md](./2024-02-XX_GAIN_FlashLoanSkimSync.md) |
| 2024-02-XX | Game | ReentrancyBid | [2024-02-XX_Game_ReentrancyBid.md](./2024-02-XX_Game_ReentrancyBid.md) |
| 2024-02-XX | MINER | bsc FlashLoanSkim | [2024-02-XX_MINER_bsc_FlashLoanSkim.md](./2024-02-XX_MINER_bsc_FlashLoanSkim.md) |
| 2024-02-XX | PANDORA | IntegerUnderflow | [2024-02-XX_PANDORA_IntegerUnderflow.md](./2024-02-XX_PANDORA_IntegerUnderflow.md) |
| 2024-02-XX | ParticleTrade | MaliciousLien | [2024-02-XX_ParticleTrade_MaliciousLien.md](./2024-02-XX_ParticleTrade_MaliciousLien.md) |
| 2024-02-XX | RuggedArt | FlashLoanNFTStaking | [2024-02-XX_RuggedArt_FlashLoanNFTStaking.md](./2024-02-XX_RuggedArt_FlashLoanNFTStaking.md) |
| 2024-02-XX | Seneca | ArbitraryCall | [2024-02-XX_Seneca_ArbitraryCall.md](./2024-02-XX_Seneca_ArbitraryCall.md) |
| 2024-02-XX | SwarmMarkets | UnauthorizedMintUnwrap | [2024-02-XX_SwarmMarkets_UnauthorizedMintUnwrap.md](./2024-02-XX_SwarmMarkets_UnauthorizedMintUnwrap.md) |
| 2024-02-XX | Zoomer | ArbitrarySelector | [2024-02-XX_Zoomer_ArbitrarySelector.md](./2024-02-XX_Zoomer_ArbitrarySelector.md) |
| 2024-03-05 | WOOFi | sPMMOracleManipulation ARB | [2024-03-05_WOOFi_sPMMOracleManipulation_ARB.md](./2024-03-05_WOOFi_sPMMOracleManipulation_ARB.md) |
| 2024-03-06 | TGBSToken | BusinessLogic BSC | [2024-03-06_TGBSToken_BusinessLogic_BSC.md](./2024-03-06_TGBSToken_BusinessLogic_BSC.md) |
| 2024-03-08 | Unizen | ArbitraryCall ETH | [2024-03-08_Unizen_ArbitraryCall_ETH.md](./2024-03-08_Unizen_ArbitraryCall_ETH.md) |
| 2024-03-14 | MOToken | BusinessLogic OP | [2024-03-14_MOToken_BusinessLogic_OP.md](./2024-03-14_MOToken_BusinessLogic_OP.md) |
| 2024-03-20 | ParaSwap | AccessControl Multichain | [2024-03-20_ParaSwap_AccessControl_Multichain.md](./2024-03-20_ParaSwap_AccessControl_Multichain.md) |
| 2024-03-23 | ARKToken | AccessControl BSC | [2024-03-23_ARKToken_AccessControl_BSC.md](./2024-03-23_ARKToken_AccessControl_BSC.md) |
| 2024-03-23 | CurioEcosystem | GovernanceAttack ETH | [2024-03-23_CurioEcosystem_GovernanceAttack_ETH.md](./2024-03-23_CurioEcosystem_GovernanceAttack_ETH.md) |
| 2024-03-25 | ZongZiToken | PriceDependency BSC | [2024-03-25_ZongZiToken_PriceDependency_BSC.md](./2024-03-25_ZongZiToken_PriceDependency_BSC.md) |
| 2024-03-28 | PrismaFi | MigrateExploit ETH | [2024-03-28_PrismaFi_MigrateExploit_ETH.md](./2024-03-28_PrismaFi_MigrateExploit_ETH.md) |
| 2024-03-XX | ALP | ArbitrarySwapCall | [2024-03-XX_ALP_ArbitrarySwapCall.md](./2024-03-XX_ALP_ArbitrarySwapCall.md) |
| 2024-03-XX | ARK | BusinessLogicAutoBurn | [2024-03-XX_ARK_BusinessLogicAutoBurn.md](./2024-03-XX_ARK_BusinessLogicAutoBurn.md) |
| 2024-03-XX | BBT | SetRegistryMint | [2024-03-XX_BBT_SetRegistryMint.md](./2024-03-XX_BBT_SetRegistryMint.md) |
| 2024-03-XX | Binemon | SweepTokenAccessControl | [2024-03-XX_Binemon_SweepTokenAccessControl.md](./2024-03-XX_Binemon_SweepTokenAccessControl.md) |
| 2024-03-XX | CGT | GovernanceTakeover | [2024-03-XX_CGT_GovernanceTakeover.md](./2024-03-XX_CGT_GovernanceTakeover.md) |
| 2024-03-XX | ETHFIN | BuybackManipulation | [2024-03-XX_ETHFIN_BuybackManipulation.md](./2024-03-XX_ETHFIN_BuybackManipulation.md) |
| 2024-03-XX | GHT | TransferFromSyncManipulation | [2024-03-XX_GHT_TransferFromSyncManipulation.md](./2024-03-XX_GHT_TransferFromSyncManipulation.md) |
| 2024-03-XX | IT | FlashLoanMintReserveManipulation | [2024-03-XX_IT_FlashLoanMintReserveManipulation.md](./2024-03-XX_IT_FlashLoanMintReserveManipulation.md) |
| 2024-03-XX | Juice | StakingRewardLogicFlaw | [2024-03-XX_Juice_StakingRewardLogicFlaw.md](./2024-03-XX_Juice_StakingRewardLogicFlaw.md) |
| 2024-03-XX | MO | BorrowRedeemLogicFlaw | [2024-03-XX_MO_BorrowRedeemLogicFlaw.md](./2024-03-XX_MO_BorrowRedeemLogicFlaw.md) |
| 2024-03-XX | Prisma | FlashLoanTroveZap | [2024-03-XX_Prisma_FlashLoanTroveZap.md](./2024-03-XX_Prisma_FlashLoanTroveZap.md) |
| 2024-03-XX | SSS | TransferLimitBypass | [2024-03-XX_SSS_TransferLimitBypass.md](./2024-03-XX_SSS_TransferLimitBypass.md) |
| 2024-03-XX | TGBS | BurnBlockBypass | [2024-03-XX_TGBS_BurnBlockBypass.md](./2024-03-XX_TGBS_BurnBlockBypass.md) |
| 2024-03-XX | UnizenIO | ArbitraryCalldata | [2024-03-XX_UnizenIO_ArbitraryCalldata.md](./2024-03-XX_UnizenIO_ArbitraryCalldata.md) |
| 2024-04-01 | ATMToken | BusinessLogic BSC | [2024-04-01_ATMToken_BusinessLogic_BSC.md](./2024-04-01_ATMToken_BusinessLogic_BSC.md) |
| 2024-04-01 | OpenLeverage | Reentrancy BSC | [2024-04-01_OpenLeverage_Reentrancy_BSC.md](./2024-04-01_OpenLeverage_Reentrancy_BSC.md) |
| 2024-04-09 | Unverified Contract 0x00C409 | Unknown Vulnerability | [2024-04-09_UnverifiedContract0x00C409_UnknownVuln.md](./2024-04-09_UnverifiedContract0x00C409_UnknownVuln.md) |
| 2024-04-12 | SumerMoney | Reentrancy Base | [2024-04-12_SumerMoney_Reentrancy_Base.md](./2024-04-12_SumerMoney_Reentrancy_Base.md) |
| 2024-04-19 | HedgeyFinance | ArbitraryCall ETH | [2024-04-19_HedgeyFinance_ArbitraryCall_ETH.md](./2024-04-19_HedgeyFinance_ArbitraryCall_ETH.md) |
| 2024-04-24 | SaitaChain | AccessControl ETH | [2024-04-24_SaitaChain_AccessControl_ETH.md](./2024-04-24_SaitaChain_AccessControl_ETH.md) |
| 2024-04-24 | YIEDL | UnverifiedInput BSC | [2024-04-24_YIEDL_UnverifiedInput_BSC.md](./2024-04-24_YIEDL_UnverifiedInput_BSC.md) |
| 2024-04-25 | NGFSToken | AccessControl BSC | [2024-04-25_NGFSToken_AccessControl_BSC.md](./2024-04-25_NGFSToken_AccessControl_BSC.md) |
| 2024-04-27 | EmberSword | AccessControl Polygon | [2024-04-27_EmberSword_AccessControl_Polygon.md](./2024-04-27_EmberSword_AccessControl_Polygon.md) |
| 2024-04-30 | PikeFinance | StorageCollision ETH | [2024-04-30_PikeFinance_StorageCollision_ETH.md](./2024-04-30_PikeFinance_StorageCollision_ETH.md) |
| 2024-04-XX | ATM | FlashLoanSkim | [2024-04-XX_ATM_FlashLoanSkim.md](./2024-04-XX_ATM_FlashLoanSkim.md) |
| 2024-04-XX | BNBX | AllowanceDrain | [2024-04-XX_BNBX_AllowanceDrain.md](./2024-04-XX_BNBX_AllowanceDrain.md) |
| 2024-04-XX | BigBangSwap | SellRewardTokenAccessControl | [2024-04-XX_BigBangSwap_SellRewardTokenAccessControl.md](./2024-04-XX_BigBangSwap_SellRewardTokenAccessControl.md) |
| 2024-04-XX | ChaingeFinance | ArbitraryCalldata | [2024-04-XX_ChaingeFinance_ArbitraryCalldata.md](./2024-04-XX_ChaingeFinance_ArbitraryCalldata.md) |
| 2024-04-XX | FIL314 | HourBurnPriceManipulation | [2024-04-XX_FIL314_HourBurnPriceManipulation.md](./2024-04-XX_FIL314_HourBurnPriceManipulation.md) |
| 2024-04-XX | GFA | RewardSelectorExploit | [2024-04-XX_GFA_RewardSelectorExploit.md](./2024-04-XX_GFA_RewardSelectorExploit.md) |
| 2024-04-XX | GROKD | UpdatePoolAccessControl | [2024-04-XX_GROKD_UpdatePoolAccessControl.md](./2024-04-XX_GROKD_UpdatePoolAccessControl.md) |
| 2024-04-XX | Hackathon | BalanceDuplicationSkim | [2024-04-XX_Hackathon_BalanceDuplicationSkim.md](./2024-04-XX_Hackathon_BalanceDuplicationSkim.md) |
| 2024-04-XX | HedgeyFinance | FlashLoanCampaign | [2024-04-XX_HedgeyFinance_FlashLoanCampaign.md](./2024-04-XX_HedgeyFinance_FlashLoanCampaign.md) |
| 2024-04-XX | HoppyFrogERC | V3FlashSwapCycle | [2024-04-XX_HoppyFrogERC_V3FlashSwapCycle.md](./2024-04-XX_HoppyFrogERC_V3FlashSwapCycle.md) |
| 2024-04-XX | MARS | ReflectionTaxSwapSyncManipulation | [2024-04-XX_MARS_ReflectionTaxSwapSyncManipulation.md](./2024-04-XX_MARS_ReflectionTaxSwapSyncManipulation.md) |
| 2024-04-XX | NGFS | DelegateCallReservesExploit | [2024-04-XX_NGFS_DelegateCallReservesExploit.md](./2024-04-XX_NGFS_DelegateCallReservesExploit.md) |
| 2024-04-XX | OpenLeverage2 | MarginTradeArbitraryDEX | [2024-04-XX_OpenLeverage2_MarginTradeArbitraryDEX.md](./2024-04-XX_OpenLeverage2_MarginTradeArbitraryDEX.md) |
| 2024-04-XX | Rico | BankDiamondFlashArbitraryTransfer | [2024-04-XX_Rico_BankDiamondFlashArbitraryTransfer.md](./2024-04-XX_Rico_BankDiamondFlashArbitraryTransfer.md) |
| 2024-04-XX | SATX | SkimSyncReserveManipulation | [2024-04-XX_SATX_SkimSyncReserveManipulation.md](./2024-04-XX_SATX_SkimSyncReserveManipulation.md) |
| 2024-04-XX | SQUID | SwapTokensSellSandwich | [2024-04-XX_SQUID_SwapTokensSellSandwich.md](./2024-04-XX_SQUID_SwapTokensSellSandwich.md) |
| 2024-04-XX | SumerMoney | RepayBorrowBehalfReentrancy | [2024-04-XX_SumerMoney_RepayBorrowBehalfReentrancy.md](./2024-04-XX_SumerMoney_RepayBorrowBehalfReentrancy.md) |
| 2024-04-XX | UPS | SkimWithoutReserveUpdate | [2024-04-XX_UPS_SkimWithoutReserveUpdate.md](./2024-04-XX_UPS_SkimWithoutReserveUpdate.md) |
| 2024-04-XX | WSM | BuyWithBNBPriceManipulation | [2024-04-XX_WSM_BuyWithBNBPriceManipulation.md](./2024-04-XX_WSM_BuyWithBNBPriceManipulation.md) |
| 2024-04-XX | XBridge | ListTokenWithdrawUnauthorized | [2024-04-XX_XBridge_ListTokenWithdrawUnauthorized.md](./2024-04-XX_XBridge_ListTokenWithdrawUnauthorized.md) |
| 2024-04-XX | YIEDL | SportVaultRedeemArbitrarySwap | [2024-04-XX_YIEDL_SportVaultRedeemArbitrarySwap.md](./2024-04-XX_YIEDL_SportVaultRedeemArbitrarySwap.md) |
| 2024-04-XX | Yield | MintDivestedBurnDivestedLogicFlaw | [2024-04-XX_Yield_MintDivestedBurnDivestedLogicFlaw.md](./2024-04-XX_Yield_MintDivestedBurnDivestedLogicFlaw.md) |
| 2024-04-XX | Z123 | ConsecutiveSwapLiquidityBurn | [2024-04-XX_Z123_ConsecutiveSwapLiquidityBurn.md](./2024-04-XX_Z123_ConsecutiveSwapLiquidityBurn.md) |
| 2024-05-10 | GalaxyFoxToken | AccessControl ETH | [2024-05-10_GalaxyFoxToken_AccessControl_ETH.md](./2024-05-10_GalaxyFoxToken_AccessControl_ETH.md) |
| 2024-05-10 | Tsuru | AccessControl Base | [2024-05-10_Tsuru_AccessControl_Base.md](./2024-05-10_Tsuru_AccessControl_Base.md) |
| 2024-05-14 | PredyFinance | AccountingError ARB | [2024-05-14_PredyFinance_AccountingError_ARB.md](./2024-05-14_PredyFinance_AccountingError_ARB.md) |
| 2024-05-14 | SonneFinance | ERC4626Inflation OP | [2024-05-14_SonneFinance_ERC4626Inflation_OP.md](./2024-05-14_SonneFinance_ERC4626Inflation_OP.md) |
| 2024-05-24 | Kraken | AccountingError Base | [2024-05-24_Kraken_AccountingError_Base.md](./2024-05-24_Kraken_AccountingError_Base.md) |
| 2024-05-26 | Normie | BusinessLogic Base | [2024-05-26_Normie_BusinessLogic_Base.md](./2024-05-26_Normie_BusinessLogic_Base.md) |
| 2024-05-28 | OrionProtocol | BusinessLogic BSC | [2024-05-28_OrionProtocol_BusinessLogic_BSC.md](./2024-05-28_OrionProtocol_BusinessLogic_BSC.md) |
| 2024-05-29 | MetaDragon | AccessControl BSC | [2024-05-29_MetaDragon_AccessControl_BSC.md](./2024-05-29_MetaDragon_AccessControl_BSC.md) |
| 2024-05-31 | TLNProtocol | PriceDependency BSC | [2024-05-31_TLNProtocol_PriceDependency_BSC.md](./2024-05-31_TLNProtocol_PriceDependency_BSC.md) |
| 2024-05-31 | DMMBitcoin | HotWalletDrain BTC | [2024-05-31_DMMBitcoin_HotWalletDrain_BTC.md](./2024-05-31_DMMBitcoin_HotWalletDrain_BTC.md) |
| 2024-05-XX | Burner | ConvertAndBurnNullToken | [2024-05-XX_Burner_ConvertAndBurnNullToken.md](./2024-05-XX_Burner_ConvertAndBurnNullToken.md) |
| 2024-05-XX | EXcommunity | GetPriceCREATE2Manipulation | [2024-05-XX_EXcommunity_GetPriceCREATE2Manipulation.md](./2024-05-XX_EXcommunity_GetPriceCREATE2Manipulation.md) |
| 2024-05-XX | GFOX | SetMerkleRootAccessControl | [2024-05-XX_GFOX_SetMerkleRootAccessControl.md](./2024-05-XX_GFOX_SetMerkleRootAccessControl.md) |
| 2024-05-XX | GPU | SelfTransferBalanceMultiplication | [2024-05-XX_GPU_SelfTransferBalanceMultiplication.md](./2024-05-XX_GPU_SelfTransferBalanceMultiplication.md) |
| 2024-05-XX | Liquiditytokens | JoinStakeLockExploit | [2024-05-XX_Liquiditytokens_JoinStakeLockExploit.md](./2024-05-XX_Liquiditytokens_JoinStakeLockExploit.md) |
| 2024-05-XX | MetaDragon | TransferToContractUnrestrictedMint | [2024-05-XX_MetaDragon_TransferToContractUnrestrictedMint.md](./2024-05-XX_MetaDragon_TransferToContractUnrestrictedMint.md) |
| 2024-05-XX | MixedSwapRouter | AlgebraSwapCallbackValidation | [2024-05-XX_MixedSwapRouter_AlgebraSwapCallbackValidation.md](./2024-05-XX_MixedSwapRouter_AlgebraSwapCallbackValidation.md) |
| 2024-05-XX | NORMIE | SkimFeeOnTransferExploit | [2024-05-XX_NORMIE_SkimFeeOnTransferExploit.md](./2024-05-XX_NORMIE_SkimFeeOnTransferExploit.md) |
| 2024-05-XX | OSN | RewardDistributionNoHoldDuration | [2024-05-XX_OSN_RewardDistributionNoHoldDuration.md](./2024-05-XX_OSN_RewardDistributionNoHoldDuration.md) |
| 2024-05-XX | PredyFinance | RegisterPairCallbackExploit | [2024-05-XX_PredyFinance_RegisterPairCallbackExploit.md](./2024-05-XX_PredyFinance_RegisterPairCallbackExploit.md) |
| 2024-05-XX | RedKeysCoin | PredictableRNG | [2024-05-XX_RedKeysCoin_PredictableRNG.md](./2024-05-XX_RedKeysCoin_PredictableRNG.md) |
| 2024-05-XX | SATURN | SetEnableSwitchManipulation | [2024-05-XX_SATURN_SetEnableSwitchManipulation.md](./2024-05-XX_SATURN_SetEnableSwitchManipulation.md) |
| 2024-05-XX | SCROLL | UniversalRouterExecute | [2024-05-XX_SCROLL_UniversalRouterExecute.md](./2024-05-XX_SCROLL_UniversalRouterExecute.md) |
| 2024-05-XX | Sonne | CompoundDonateExploit | [2024-05-XX_Sonne_CompoundDonateExploit.md](./2024-05-XX_Sonne_CompoundDonateExploit.md) |
| 2024-05-XX | TCH | BurnTokenSignatureMalleable | [2024-05-XX_TCH_BurnTokenSignatureMalleable.md](./2024-05-XX_TCH_BurnTokenSignatureMalleable.md) |
| 2024-05-XX | TGC | SelectorBasedRewardManipulation | [2024-05-XX_TGC_SelectorBasedRewardManipulation.md](./2024-05-XX_TGC_SelectorBasedRewardManipulation.md) |
| 2024-05-XX | TSURU | OnERC1155ReceivedUnauthorized | [2024-05-XX_TSURU_OnERC1155ReceivedUnauthorized.md](./2024-05-XX_TSURU_OnERC1155ReceivedUnauthorized.md) |
| 2024-05-XX | Tradeonorion | RedeemAtomicSignatureBypass | [2024-05-XX_Tradeonorion_RedeemAtomicSignatureBypass.md](./2024-05-XX_Tradeonorion_RedeemAtomicSignatureBypass.md) |
| 2024-06-02 | Velocore | InvariantFlaw zkSync | [2024-06-02_Velocore_InvariantFlaw_zkSync.md](./2024-06-02_Velocore_InvariantFlaw_zkSync.md) |
| 2024-06-10 | UwULend | CurveOracleManipulation ETH | [2024-06-10_UwULend_CurveOracleManipulation_ETH.md](./2024-06-10_UwULend_CurveOracleManipulation_ETH.md) |
| 2024-06-13 | UwU Lend | Oracle Price Manipulation (2nd Attack) | [2024-06-13_UwuLend_Second_OraclePriceManipulation.md](./2024-06-13_UwuLend_Second_OraclePriceManipulation.md) |
| 2024-06-XX | APEMAGA | FamilySyncPriceManipulation | [2024-06-XX_APEMAGA_FamilySyncPriceManipulation.md](./2024-06-XX_APEMAGA_FamilySyncPriceManipulation.md) |
| 2024-06-XX | Bazaar | ExitPoolArbitraryHolder | [2024-06-XX_Bazaar_ExitPoolArbitraryHolder.md](./2024-06-XX_Bazaar_ExitPoolArbitraryHolder.md) |
| 2024-06-XX | Crb2 | BuySellTransferIteration | [2024-06-XX_Crb2_BuySellTransferIteration.md](./2024-06-XX_Crb2_BuySellTransferIteration.md) |
| 2024-06-XX | DysonMoney | MintHarvestRedeemLogicFlaw | [2024-06-XX_DysonMoney_MintHarvestRedeemLogicFlaw.md](./2024-06-XX_DysonMoney_MintHarvestRedeemLogicFlaw.md) |
| 2024-06-XX | INcufi | StakeZeroDayWithdralSwapCommision | [2024-06-XX_INcufi_StakeZeroDayWithdralSwapCommision.md](./2024-06-XX_INcufi_StakeZeroDayWithdralSwapCommision.md) |
| 2024-06-XX | JokInTheBox | UnstakeIndexZeroRepeat | [2024-06-XX_JokInTheBox_UnstakeIndexZeroRepeat.md](./2024-06-XX_JokInTheBox_UnstakeIndexZeroRepeat.md) |
| 2024-06-XX | MineSTM | UpdateAllowanceSellExploit | [2024-06-XX_MineSTM_UpdateAllowanceSellExploit.md](./2024-06-XX_MineSTM_UpdateAllowanceSellExploit.md) |
| 2024-06-XX | NCD | PreStartTimeRewardsAck | [2024-06-XX_NCD_PreStartTimeRewardsAck.md](./2024-06-XX_NCD_PreStartTimeRewardsAck.md) |
| 2024-06-XX | SteamSwap | UpdateAllowanceSellLarge | [2024-06-XX_SteamSwap_UpdateAllowanceSellLarge.md](./2024-06-XX_SteamSwap_UpdateAllowanceSellLarge.md) |
| 2024-06-XX | UwuLend | First OraclePriceManipulation | [2024-06-XX_UwuLend_First_OraclePriceManipulation.md](./2024-06-XX_UwuLend_First_OraclePriceManipulation.md) |
| 2024-06-XX | Velocore | ExecutePoolAccountingBug | [2024-06-XX_Velocore_ExecutePoolAccountingBug.md](./2024-06-XX_Velocore_ExecutePoolAccountingBug.md) |
| 2024-06-XX | WIFCOIN | ClaimEarnedBurnRateRepeat | [2024-06-XX_WIFCOIN_ClaimEarnedBurnRateRepeat.md](./2024-06-XX_WIFCOIN_ClaimEarnedBurnRateRepeat.md) |
| 2024-06-XX | Will | PlaceSellOrderExpiredSettlement | [2024-06-XX_Will_PlaceSellOrderExpiredSettlement.md](./2024-06-XX_Will_PlaceSellOrderExpiredSettlement.md) |
| 2024-06-XX | YYS | UpdateAllowanceSellExploit | [2024-06-XX_YYS_UpdateAllowanceSellExploit.md](./2024-06-XX_YYS_UpdateAllowanceSellExploit.md) |
| 2024-07-05 | DeFiPlaza | PrecisionLoss ETH | [2024-07-05_DeFiPlaza_PrecisionLoss_ETH.md](./2024-07-05_DeFiPlaza_PrecisionLoss_ETH.md) |
| 2024-07-12 | DoughFinance | FlashLoanArbitraryCall ETH | [2024-07-12_DoughFinance_FlashLoanArbitraryCall_ETH.md](./2024-07-12_DoughFinance_FlashLoanArbitraryCall_ETH.md) |
| 2024-07-13 | GAX | UnvalidatedLowLevelCall | [2024-07-13_GAX_UnvalidatedLowLevelCall.md](./2024-07-13_GAX_UnvalidatedLowLevelCall.md) |
| 2024-07-14 | MinterestFinance | Reentrancy Mantle | [2024-07-14_MinterestFinance_Reentrancy_Mantle.md](./2024-07-14_MinterestFinance_Reentrancy_Mantle.md) |
| 2024-07-15 | LW | TransferFromExploit | [2024-07-15_LW_TransferFromExploit.md](./2024-07-15_LW_TransferFromExploit.md) |
| 2024-07-16 | LIFI | DiamondFacetArbitraryCall ETH | [2024-07-16_LIFI_DiamondFacetArbitraryCall_ETH.md](./2024-07-16_LIFI_DiamondFacetArbitraryCall_ETH.md) |
| 2024-07-18 | MEVbot | 0xdd7c UniswapV3CallbackExploit | [2024-07-18_MEVbot_0xdd7c_UniswapV3CallbackExploit.md](./2024-07-18_MEVbot_0xdd7c_UniswapV3CallbackExploit.md) |
| 2024-07-18 | WazirX | MultisigManipulation ETH | [2024-07-18_WazirX_MultisigManipulation_ETH.md](./2024-07-18_WazirX_MultisigManipulation_ETH.md) |
| 2024-07-20 | MRP | ReentrancyFallback | [2024-07-20_MRP_ReentrancyFallback.md](./2024-07-20_MRP_ReentrancyFallback.md) |
| 2024-07-21 | UPS | BusinessLogic BSC | [2024-07-21_UPS_BusinessLogic_BSC.md](./2024-07-21_UPS_BusinessLogic_BSC.md) |
| 2024-07-23 | Spectra | ArbitraryCall ETH | [2024-07-23_Spectra_ArbitraryCall_ETH.md](./2024-07-23_Spectra_ArbitraryCall_ETH.md) |
| 2024-07-25 | SBT | FlashLoanLoanDrain | [2024-07-25_SBT_FlashLoanLoanDrain.md](./2024-07-25_SBT_FlashLoanLoanDrain.md) |
| 2024-07-28 | UnverifiedContr | 0x452E25 UniswapV3CallbackExploit | [2024-07-28_UnverifiedContr_0x452E25_UniswapV3CallbackExploit.md](./2024-07-28_UnverifiedContr_0x452E25_UniswapV3CallbackExploit.md) |
| 2024-08-01 | Convergence | UnverifiedInput ETH | [2024-08-01_Convergence_UnverifiedInput_ETH.md](./2024-08-01_Convergence_UnverifiedInput_ETH.md) |
| 2024-08-06 | RoninBridge | Misconfiguration ETH | [2024-08-06_RoninBridge_Misconfiguration_ETH.md](./2024-08-06_RoninBridge_Misconfiguration_ETH.md) |
| 2024-08-12 | AAVERepayAdapter | ApprovalExploit | [2024-08-12_AAVERepayAdapter_ApprovalExploit.md](./2024-08-12_AAVERepayAdapter_ApprovalExploit.md) |
| 2024-08-12 | iVestToken | DoubleAccounting BSC | [2024-08-12_iVestToken_DoubleAccounting_BSC.md](./2024-08-12_iVestToken_DoubleAccounting_BSC.md) |
| 2024-08-13 | VOW | Misconfiguration ETH | [2024-08-13_VOW_Misconfiguration_ETH.md](./2024-08-13_VOW_Misconfiguration_ETH.md) |
| 2024-08-14 | COCO | FlashLoanTransferFromDrain | [2024-08-14_COCO_FlashLoanTransferFromDrain.md](./2024-08-14_COCO_FlashLoanTransferFromDrain.md) |
| 2024-08-20 | NovaXM2E | StakingPriceSandwich | [2024-08-20_NovaXM2E_StakingPriceSandwich.md](./2024-08-20_NovaXM2E_StakingPriceSandwich.md) |
| 2024-08-25 | OMPxContract | PriceManipulation | [2024-08-25_OMPxContract_PriceManipulation.md](./2024-08-25_OMPxContract_PriceManipulation.md) |
| 2024-08-28 | YodlRouter | TransferFeeExploit | [2024-08-28_YodlRouter_TransferFeeExploit.md](./2024-08-28_YodlRouter_TransferFeeExploit.md) |
| 2024-08-29 | Unverified667d | AccessControl | [2024-08-29_Unverified667d_AccessControl.md](./2024-08-29_Unverified667d_AccessControl.md) |
| 2024-08-30 | Zenterest | StaleOracleBorrow | [2024-08-30_Zenterest_StaleOracleBorrow.md](./2024-08-30_Zenterest_StaleOracleBorrow.md) |
| 2024-09-03 | Penpie | ReentrancyRewardInflation ETH | [2024-09-03_Penpie_ReentrancyRewardInflation_ETH.md](./2024-09-03_Penpie_ReentrancyRewardInflation_ETH.md) |
| 2024-09-04 | Pythia | ReentrancyStakingDrain | [2024-09-04_Pythia_ReentrancyStakingDrain.md](./2024-09-04_Pythia_ReentrancyStakingDrain.md) |
| 2024-09-04 | Unverified16d0 | MultiCallTransferFrom | [2024-09-04_Unverified16d0_MultiCallTransferFrom.md](./2024-09-04_Unverified16d0_MultiCallTransferFrom.md) |
| 2024-09-04 | Unveriifieda89f | SwapCallbackDrain | [2024-09-04_Unveriifieda89f_SwapCallbackDrain.md](./2024-09-04_Unveriifieda89f_SwapCallbackDrain.md) |
| 2024-09-05 | AIRBTC | CustomSelectorDrain | [2024-09-05_AIRBTC_CustomSelectorDrain.md](./2024-09-05_AIRBTC_CustomSelectorDrain.md) |
| 2024-09-06 | Unverified03f9 | SwapCallback | [2024-09-06_Unverified03f9_SwapCallback.md](./2024-09-06_Unverified03f9_SwapCallback.md) |
| 2024-09-06 | Unverified5697 | TransferFromExploit | [2024-09-06_Unverified5697_TransferFromExploit.md](./2024-09-06_Unverified5697_TransferFromExploit.md) |
| 2024-09-10 | CaterpillarCoin | Create2LPBurn | [2024-09-10_CaterpillarCoin_Create2LPBurn.md](./2024-09-10_CaterpillarCoin_Create2LPBurn.md) |
| 2024-09-16 | Inferno | SlippageProtection ETH | [2024-09-16_Inferno_SlippageProtection_ETH.md](./2024-09-16_Inferno_SlippageProtection_ETH.md) |
| 2024-09-11 | WXETA | InitializeMintExploit | [2024-09-11_WXETA_InitializeMintExploit.md](./2024-09-11_WXETA_InitializeMintExploit.md) |
| 2024-09-12 | DOGGO | TokenSelfBalanceExploit | [2024-09-12_DOGGO_TokenSelfBalanceExploit.md](./2024-09-12_DOGGO_TokenSelfBalanceExploit.md) |
| 2024-09-13 | INUMI | AccessControlDrain | [2024-09-13_INUMI_AccessControlDrain.md](./2024-09-13_INUMI_AccessControlDrain.md) |
| 2024-09-14 | PLN | TransferFromZeroAmount | [2024-09-14_PLN_TransferFromZeroAmount.md](./2024-09-14_PLN_TransferFromZeroAmount.md) |
| 2024-09-17 | MARA | EncodedCallExploit | [2024-09-17_MARA_EncodedCallExploit.md](./2024-09-17_MARA_EncodedCallExploit.md) |
| 2024-09-17 | OTSeaStaking | DuplicateIndexDrain | [2024-09-17_OTSeaStaking_DuplicateIndexDrain.md](./2024-09-17_OTSeaStaking_DuplicateIndexDrain.md) |
| 2024-09-18 | PestoToken | SelfBalanceThresholdExploit | [2024-09-18_PestoToken_SelfBalanceThresholdExploit.md](./2024-09-18_PestoToken_SelfBalanceThresholdExploit.md) |
| 2024-09-18 | unverified | 766a PancakeV3CallbackExploit | [2024-09-18_unverified_766a_PancakeV3CallbackExploit.md](./2024-09-18_unverified_766a_PancakeV3CallbackExploit.md) |
| 2024-09-19 | BananaGun | TelegramBotOracle ETH | [2024-09-19_BananaGun_TelegramBotOracle_ETH.md](./2024-09-19_BananaGun_TelegramBotOracle_ETH.md) |
| 2024-09-20 | Shezmu | BusinessLogic ETH | [2024-09-20_Shezmu_BusinessLogic_ETH.md](./2024-09-20_Shezmu_BusinessLogic_ETH.md) |
| 2024-09-22 | Bankroll | UnverifiedInput BSC | [2024-09-22_Bankroll_UnverifiedInput_BSC.md](./2024-09-22_Bankroll_UnverifiedInput_BSC.md) |
| 2024-09-23 | HANAToken | SelfBalanceExploit | [2024-09-23_HANAToken_SelfBalanceExploit.md](./2024-09-23_HANAToken_SelfBalanceExploit.md) |
| 2024-09-26 | OnyxDAO | UnverifiedInput ETH | [2024-09-26_OnyxDAO_UnverifiedInput_ETH.md](./2024-09-26_OnyxDAO_UnverifiedInput_ETH.md) |
| 2024-09-26 | RockX | UniBTC Misconfiguration ETH | [2024-09-26_RockX_UniBTC_Misconfiguration_ETH.md](./2024-09-26_RockX_UniBTC_Misconfiguration_ETH.md) |
| 2024-10-05 | AIZPTToken | SelfTransferBurn | [2024-10-05_AIZPTToken_SelfTransferBurn.md](./2024-10-05_AIZPTToken_SelfTransferBurn.md) |
| 2024-10-05 | EGAToken | SlippageProtection BSC | [2024-10-05_EGAToken_SlippageProtection_BSC.md](./2024-10-05_EGAToken_SlippageProtection_BSC.md) |
| 2024-10-10 | HYDT | OracleMintManipulation | [2024-10-10_HYDT_OracleMintManipulation.md](./2024-10-10_HYDT_OracleMintManipulation.md) |
| 2024-10-06 | SASHAToken | MintExploit | [2024-10-06_SASHAToken_MintExploit.md](./2024-10-06_SASHAToken_MintExploit.md) |
| 2024-10-16 | RadiantCapital | MultisigCompromise BSC ARB | [2024-10-16_RadiantCapital_MultisigCompromise_BSC_ARB.md](./2024-10-16_RadiantCapital_MultisigCompromise_BSC_ARB.md) |
| 2024-10-22 | VISTA | FlashLoanFreeze | [2024-10-22_VISTA_FlashLoanFreeze.md](./2024-10-22_VISTA_FlashLoanFreeze.md) |
| 2024-10-13 | MorphoBlue | BundlerAccessControl ETH | [2024-10-13_MorphoBlue_BundlerAccessControl_ETH.md](./2024-10-13_MorphoBlue_BundlerAccessControl_ETH.md) |
| 2024-10-11 | P719Token | SellMechanism | [2024-10-11_P719Token_SellMechanism.md](./2024-10-11_P719Token_SellMechanism.md) |
| 2024-10-22 | Erc20transfer | ArbitraryTransferFrom | [2024-10-22_Erc20transfer_ArbitraryTransferFrom.md](./2024-10-22_Erc20transfer_ArbitraryTransferFrom.md) |
| 2024-10-26 | CompoundFork | FlashloanAttack Base | [2024-10-26_CompoundFork_FlashloanAttack_Base.md](./2024-10-26_CompoundFork_FlashloanAttack_Base.md) |
| 2024-10-02 | LavaLending | PriceOracleManipulation | [2024-10-02_LavaLending_PriceOracleManipulation.md](./2024-10-02_LavaLending_PriceOracleManipulation.md) |
| 2024-10-01 | FireToken | TransferLPDrainExploit | [2024-10-01_FireToken_TransferLPDrainExploit.md](./2024-10-01_FireToken_TransferLPDrainExploit.md) |
| 2024-10-29 | BUBAI | TransferFromAllowanceExploit | [2024-10-29_BUBAI_TransferFromAllowanceExploit.md](./2024-10-29_BUBAI_TransferFromAllowanceExploit.md) |
| 2024-10-31 | M2Exchange | HotWalletDrain ETH BTC SOL | [2024-10-31_M2Exchange_HotWalletDrain_ETH_BTC_SOL.md](./2024-10-31_M2Exchange_HotWalletDrain_ETH_BTC_SOL.md) |
| 2024-11-07 | ChiSale | FlashLoanFrontrun | [2024-11-07_ChiSale_FlashLoanFrontrun.md](./2024-11-07_ChiSale_FlashLoanFrontrun.md) |
| 2024-11-07 | CoW | SwapCallbackDrain | [2024-11-07_CoW_SwapCallbackDrain.md](./2024-11-07_CoW_SwapCallbackDrain.md) |
| 2024-11-05 | RPP | FlashLoanPriceManipulation | [2024-11-05_RPP_FlashLoanPriceManipulation.md](./2024-11-05_RPP_FlashLoanPriceManipulation.md) |
| 2024-11-26 | NFTG | FlashLoanRewardDrain | [2024-11-26_NFTG_FlashLoanRewardDrain.md](./2024-11-26_NFTG_FlashLoanRewardDrain.md) |
| 2024-11-10 | BGM | PriceDependency BSC | [2024-11-10_BGM_PriceDependency_BSC.md](./2024-11-10_BGM_PriceDependency_BSC.md) |
| 2024-11-09 | X319 | UnprotectedClaimEther | [2024-11-09_X319_UnprotectedClaimEther.md](./2024-11-09_X319_UnprotectedClaimEther.md) |
| 2024-11-11 | DeltaPrime | Reentrancy ARB | [2024-11-11_DeltaPrime_Reentrancy_ARB.md](./2024-11-11_DeltaPrime_Reentrancy_ARB.md) |
| 2024-11-14 | vETH | PriceDependency ETH | [2024-11-14_vETH_PriceDependency_ETH.md](./2024-11-14_vETH_PriceDependency_ETH.md) |
| 2024-11-17 | MFT | IntegerTruncation | [2024-11-17_MFT_IntegerTruncation.md](./2024-11-17_MFT_IntegerTruncation.md) |
| 2024-11-19 | PolterFinance | EmptyMarket FTM | [2024-11-19_PolterFinance_EmptyMarket_FTM.md](./2024-11-19_PolterFinance_EmptyMarket_FTM.md) |
| 2024-11-20 | MainnetSettler | ArbitraryExecution | [2024-11-20_MainnetSettler_ArbitraryExecution.md](./2024-11-20_MainnetSettler_ArbitraryExecution.md) |
| 2024-11-21 | Matez | IntegerTruncationStaking | [2024-11-21_Matez_IntegerTruncationStaking.md](./2024-11-21_Matez_IntegerTruncationStaking.md) |
| 2024-11-24 | proxy | b7e1 OrderManipulation | [2024-11-24_proxy_b7e1_OrderManipulation.md](./2024-11-24_proxy_b7e1_OrderManipulation.md) |
| 2024-11-23 | Ak1111 | UnprotectedLzReceive | [2024-11-23_Ak1111_UnprotectedLzReceive.md](./2024-11-23_Ak1111_UnprotectedLzReceive.md) |
| 2024-11-24 | DCFToken | SlippageProtection BSC | [2024-11-24_DCFToken_SlippageProtection_BSC.md](./2024-11-24_DCFToken_SlippageProtection_BSC.md) |
| 2024-12-03 | BYCToken | BusinessLogic BSC | [2024-12-03_BYCToken_BusinessLogic_BSC.md](./2024-12-03_BYCToken_BusinessLogic_BSC.md) |
| 2024-12-04 | VestraDAO | BusinessLogic ETH | [2024-12-04_VestraDAO_BusinessLogic_ETH.md](./2024-12-04_VestraDAO_BusinessLogic_ETH.md) |
| 2024-12-10 | CloberDEX | Reentrancy Base | [2024-12-10_CloberDEX_Reentrancy_Base.md](./2024-12-10_CloberDEX_Reentrancy_Base.md) |
| 2024-12-10 | UnknownProtocol | AccessControl BSC | [2024-12-10_UnknownProtocol_AccessControl_BSC.md](./2024-12-10_UnknownProtocol_AccessControl_BSC.md) |
| 2024-12-10 | DeXeDAO | AccessControl BSC | [2024-12-10_DeXeDAO_AccessControl_BSC.md](./2024-12-10_DeXeDAO_AccessControl_BSC.md) |
| 2024-12-11 | LABUBU | TransferFeeManipulation | [2024-12-11_LABUBU_TransferFeeManipulation.md](./2024-12-11_LABUBU_TransferFeeManipulation.md) |
| 2024-12-15 | Pledge | SwapTokenExploit | [2024-12-15_Pledge_SwapTokenExploit.md](./2024-12-15_Pledge_SwapTokenExploit.md) |
| 2024-12-17 | GemPad | Reentrancy ETH | [2024-12-17_GemPad_Reentrancy_ETH.md](./2024-12-17_GemPad_Reentrancy_ETH.md) |
| 2024-12-14 | JHY | DividendManipulation | [2024-12-14_JHY_DividendManipulation.md](./2024-12-14_JHY_DividendManipulation.md) |
| 2024-12-16 | BTC24H | LockBypassExploit | [2024-12-16_BTC24H_LockBypassExploit.md](./2024-12-16_BTC24H_LockBypassExploit.md) |
| 2024-12-18 | SlurpyCoin | TransferFeeLoop | [2024-12-18_SlurpyCoin_TransferFeeLoop.md](./2024-12-18_SlurpyCoin_TransferFeeLoop.md) |
| 2024-12-23 | Moonhacker | FlashLoanBorrow | [2024-12-23_Moonhacker_FlashLoanBorrow.md](./2024-12-23_Moonhacker_FlashLoanBorrow.md) |
| 2024-12-27 | Bizness | SplitLockReentrancy | [2024-12-27_Bizness_SplitLockReentrancy.md](./2024-12-27_Bizness_SplitLockReentrancy.md) |
| 2024-12-29 | FEG | AccessControl ETH | [2024-12-29_FEG_AccessControl_ETH.md](./2024-12-29_FEG_AccessControl_ETH.md) |

---

[← Back to main index](../README.md)
