# 2023 DeFi Security Incidents

A high-volume year with 266 incidents. Flash loan price manipulation, access control failures, and read-only reentrancy across L2 chains (Arbitrum, Optimism, Polygon) were the dominant patterns.

**Total incidents: 266**

---

## Top Vulnerability Types

| Type | Count |
|------|-------|
| FlashLoan | 12 |
| AccessControl | 11 |
| Reentrancy | 10 |
| PriceManipulation | 8 |
| FlashLoanPriceManipulation | 7 |
| BusinessLogic BSC | 6 |
| TokenLogic | 6 |
| PriceDependency BSC | 4 |
| BusinessLogic ETH | 4 |
| Reentrancy ETH | 4 |

---

## Incident List

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2023-01-03 | GDSToken | BusinessLogic BSC | [2023-01-03_GDSToken_BusinessLogic_BSC.md](./2023-01-03_GDSToken_BusinessLogic_BSC.md) |
| 2023-01-08 | GDS | FlashLoanPriceManipulation | [2023-01-08_GDS_FlashLoanPriceManipulation.md](./2023-01-08_GDS_FlashLoanPriceManipulation.md) |
| 2023-01-10 | BRAToken | BusinessLogic BSC | [2023-01-10_BRAToken_BusinessLogic_BSC.md](./2023-01-10_BRAToken_BusinessLogic_BSC.md) |
| 2023-01-12 | BEVO | ReflectiveTokenExploit | [2023-01-12_BEVO_ReflectiveTokenExploit.md](./2023-01-12_BEVO_ReflectiveTokenExploit.md) |
| 2023-01-13 | RoeFinance | FlashLoanLPManipulation | [2023-01-13_RoeFinance_FlashLoanLPManipulation.md](./2023-01-13_RoeFinance_FlashLoanLPManipulation.md) |
| 2023-01-13 | UFDao | BusinessLogicFlaw | [2023-01-13_UFDao_BusinessLogicFlaw.md](./2023-01-13_UFDao_BusinessLogicFlaw.md) |
| 2023-01-15 | MidasCapital | PriceDependency Polygon | [2023-01-15_MidasCapital_PriceDependency_Polygon.md](./2023-01-15_MidasCapital_PriceDependency_Polygon.md) |
| 2023-01-16 | ThoreumFinance | ReentrancyTokenBurn | [2023-01-16_ThoreumFinance_ReentrancyTokenBurn.md](./2023-01-16_ThoreumFinance_ReentrancyTokenBurn.md) |
| 2023-01-18 | Midas | OraclePriceManipulation | [2023-01-18_Midas_OraclePriceManipulation.md](./2023-01-18_Midas_OraclePriceManipulation.md) |
| 2023-01-18 | OmniEstate | StakingLogicFlaw | [2023-01-18_OmniEstate_StakingLogicFlaw.md](./2023-01-18_OmniEstate_StakingLogicFlaw.md) |
| 2023-01-19 | QTN | ReflectiveTaxSandwich | [2023-01-19_QTN_ReflectiveTaxSandwich.md](./2023-01-19_QTN_ReflectiveTaxSandwich.md) |
| 2023-01-19 | SHOCO | ReflectiveDeliverSkim | [2023-01-19_SHOCO_ReflectiveDeliverSkim.md](./2023-01-19_SHOCO_ReflectiveDeliverSkim.md) |
| 2023-01-19 | Upswing | ReflectivePressureExploit | [2023-01-19_Upswing_ReflectivePressureExploit.md](./2023-01-19_Upswing_ReflectivePressureExploit.md) |
| 2023-01-25 | TINU | ReflectiveDeliverBalancer | [2023-01-25_TINU_ReflectiveDeliverBalancer.md](./2023-01-25_TINU_ReflectiveDeliverBalancer.md) |
| 2023-02-01 | BonqDAO | OracleManipulation Polygon | [2023-02-01_BonqDAO_OracleManipulation_Polygon.md](./2023-02-01_BonqDAO_OracleManipulation_Polygon.md) |
| 2023-02-02 | BonqDAO | OracleManipulation | [2023-02-02_BonqDAO_OracleManipulation.md](./2023-02-02_BonqDAO_OracleManipulation.md) |
| 2023-02-02 | Orion | ReentrancyFakeToken | [2023-02-02_Orion_ReentrancyFakeToken.md](./2023-02-02_Orion_ReentrancyFakeToken.md) |
| 2023-02-07 | CowSwap | ApprovalAbuse | [2023-02-07_CowSwap_ApprovalAbuse.md](./2023-02-07_CowSwap_ApprovalAbuse.md) |
| 2023-02-09 | FDP | ReflectiveSkimExploit | [2023-02-09_FDP_ReflectiveSkimExploit.md](./2023-02-09_FDP_ReflectiveSkimExploit.md) |
| 2023-02-09 | dForce | ReadOnlyReentrancy ARB | [2023-02-09_dForce_ReadOnlyReentrancy_ARB.md](./2023-02-09_dForce_ReadOnlyReentrancy_ARB.md) |
| 2023-02-10 | dForce | Reentrancy | [2023-02-10_dForce_Reentrancy.md](./2023-02-10_dForce_Reentrancy.md) |
| 2023-02-13 | Sheep | ReflectiveSkim | [2023-02-13_Sheep_ReflectiveSkim.md](./2023-02-13_Sheep_ReflectiveSkim.md) |
| 2023-02-13 | Starlink | FlashLoanTokenBurn | [2023-02-13_Starlink_FlashLoanTokenBurn.md](./2023-02-13_Starlink_FlashLoanTokenBurn.md) |
| 2023-02-15 | USDs | CurvePoolManipulation | [2023-02-15_USDs_CurvePoolManipulation.md](./2023-02-15_USDs_CurvePoolManipulation.md) |
| 2023-02-16 | Platypus | FlashLoanStablecoin | [2023-02-16_Platypus_FlashLoanStablecoin.md](./2023-02-16_Platypus_FlashLoanStablecoin.md) |
| 2023-02-17 | Dexible | ArbitraryCall ETH | [2023-02-17_Dexible_ArbitraryCall_ETH.md](./2023-02-17_Dexible_ArbitraryCall_ETH.md) |
| 2023-02-17 | SwapX | FlashLoanManipulation | [2023-02-17_SwapX_FlashLoanManipulation.md](./2023-02-17_SwapX_FlashLoanManipulation.md) |
| 2023-02-24 | DYNA | StakingReentrancy | [2023-02-24_DYNA_StakingReentrancy.md](./2023-02-24_DYNA_StakingReentrancy.md) |
| 2023-02-24 | EFVault | PriceManipulation ETH | [2023-02-24_EFVault_PriceManipulation_ETH.md](./2023-02-24_EFVault_PriceManipulation_ETH.md) |
| 2023-02-27 | EFVault | PriceManipulation | [2023-02-27_EFVault_PriceManipulation.md](./2023-02-27_EFVault_PriceManipulation.md) |
| 2023-02-27 | LaunchZone | ProxyStorageCollision | [2023-02-27_LaunchZone_ProxyStorageCollision.md](./2023-02-27_LaunchZone_ProxyStorageCollision.md) |
| 2023-02-27 | RevertFinance | ArbitrarySwap | [2023-02-27_RevertFinance_ArbitrarySwap.md](./2023-02-27_RevertFinance_ArbitrarySwap.md) |
| 2023-02-27 | swapX | AccessControl BSC | [2023-02-27_swapX_AccessControl_BSC.md](./2023-02-27_swapX_AccessControl_BSC.md) |
| 2023-03-01 | Phoenix | DelegateCallSwapAccessControl | [2023-03-01_Phoenix_DelegateCallSwapAccessControl.md](./2023-03-01_Phoenix_DelegateCallSwapAccessControl.md) |
| 2023-03-07 | BIGFI | FlashLoanPriceManipulation | [2023-03-07_BIGFI_FlashLoanPriceManipulation.md](./2023-03-07_BIGFI_FlashLoanPriceManipulation.md) |
| 2023-03-11 | DKP | SpotOracleManipulation | [2023-03-11_DKP_SpotOracleManipulation.md](./2023-03-11_DKP_SpotOracleManipulation.md) |
| 2023-03-13 | EulerFinance | DonateToReserves ETH | [2023-03-13_EulerFinance_DonateToReserves_ETH.md](./2023-03-13_EulerFinance_DonateToReserves_ETH.md) |
| 2023-03-14 | Thena | FlashLoanGauge | [2023-03-14_Thena_FlashLoanGauge.md](./2023-03-14_Thena_FlashLoanGauge.md) |
| 2023-03-15 | poolz | IntegerOverflow | [2023-03-15_poolz_IntegerOverflow.md](./2023-03-15_poolz_IntegerOverflow.md) |
| 2023-03-17 | ParaSpace | NFTReentrancy ETH | [2023-03-17_ParaSpace_NFTReentrancy_ETH.md](./2023-03-17_ParaSpace_NFTReentrancy_ETH.md) |
| 2023-03-28 | SafeMoon | PublicBurnLP BSC | [2023-03-28_SafeMoon_PublicBurnLP_BSC.md](./2023-03-28_SafeMoon_PublicBurnLP_BSC.md) |
| 2023-04-01 | Allbridge | PriceDependency BSC | [2023-04-01_Allbridge_PriceDependency_BSC.md](./2023-04-01_Allbridge_PriceDependency_BSC.md) |
| 2023-04-02 | LowCarbCrusader | BusinessLogic ETH | [2023-04-02_LowCarbCrusader_BusinessLogic_ETH.md](./2023-04-02_LowCarbCrusader_BusinessLogic_ETH.md) |
| 2023-04-04 | Sentiment | BalancerOracleManipulation ARB | [2023-04-04_Sentiment_BalancerOracleManipulation_ARB.md](./2023-04-04_Sentiment_BalancerOracleManipulation_ARB.md) |
| 2023-04-09 | Sentiment | ReentrancyAave | [2023-04-09_Sentiment_ReentrancyAave.md](./2023-04-09_Sentiment_ReentrancyAave.md) |
| 2023-04-09 | SushiSwap | RouteProcessor ETH | [2023-04-09_SushiSwap_RouteProcessor_ETH.md](./2023-04-09_SushiSwap_RouteProcessor_ETH.md) |
| 2023-04-11 | MetaPoint | AccessControl BSC | [2023-04-11_MetaPoint_AccessControl_BSC.md](./2023-04-11_MetaPoint_AccessControl_BSC.md) |
| 2023-04-11 | Paribus | Reentrancy ARB | [2023-04-11_Paribus_Reentrancy_ARB.md](./2023-04-11_Paribus_Reentrancy_ARB.md) |
| 2023-04-13 | yearnFinance | MisconfiguredVault ETH | [2023-04-13_yearnFinance_MisconfiguredVault_ETH.md](./2023-04-13_yearnFinance_MisconfiguredVault_ETH.md) |
| 2023-04-14 | OLIFE | DeliverReflectionDrain | [2023-04-14_OLIFE_DeliverReflectionDrain.md](./2023-04-14_OLIFE_DeliverReflectionDrain.md) |
| 2023-04-15 | HundredFinance | ERC4626Inflation OP | [2023-04-15_HundredFinance_ERC4626Inflation_OP.md](./2023-04-15_HundredFinance_ERC4626Inflation_OP.md) |
| 2023-04-16 | Paribus | ReentrancyLending | [2023-04-16_Paribus_ReentrancyLending.md](./2023-04-16_Paribus_ReentrancyLending.md) |
| 2023-04-18 | Swapos | InitialReserveManipulation | [2023-04-18_Swapos_InitialReserveManipulation.md](./2023-04-18_Swapos_InitialReserveManipulation.md) |
| 2023-04-22 | 0vix | FlashLoanOracleManipulation | [2023-04-22_0vix_FlashLoanOracleManipulation.md](./2023-04-22_0vix_FlashLoanOracleManipulation.md) |
| 2023-04-25 | Axioma | PresalePriceArbitrage | [2023-04-25_Axioma_PresalePriceArbitrage.md](./2023-04-25_Axioma_PresalePriceArbitrage.md) |
| 2023-04-28 | 0vixProtocol | PriceDependency Polygon | [2023-04-28_0vixProtocol_PriceDependency_Polygon.md](./2023-04-28_0vixProtocol_PriceDependency_Polygon.md) |
| 2023-04-28 | SushiSwap | RouterApproval | [2023-04-28_SushiSwap_RouterApproval.md](./2023-04-28_SushiSwap_RouterApproval.md) |
| 2023-04-30 | SiloFinance | InterestRateManipulation | [2023-04-30_SiloFinance_InterestRateManipulation.md](./2023-04-30_SiloFinance_InterestRateManipulation.md) |
| 2023-05-01 | LevelFinance | ReferralClaimDrain BSC | [2023-05-01_LevelFinance_ReferralClaimDrain_BSC.md](./2023-05-01_LevelFinance_ReferralClaimDrain_BSC.md) |
| 2023-05-02 | Melo | MintNoAccessControl | [2023-05-02_Melo_MintNoAccessControl.md](./2023-05-02_Melo_MintNoAccessControl.md) |
| 2023-05-05 | DEI | BurnFromExploit ARB | [2023-05-05_DEI_BurnFromExploit_ARB.md](./2023-05-05_DEI_BurnFromExploit_ARB.md) |
| 2023-05-05 | GPT | SkimLoopFeeManipulation | [2023-05-05_GPT_SkimLoopFeeManipulation.md](./2023-05-05_GPT_SkimLoopFeeManipulation.md) |
| 2023-05-07 | BabyDogeCoin | FlashLoanFee | [2023-05-07_BabyDogeCoin_FlashLoanFee.md](./2023-05-07_BabyDogeCoin_FlashLoanFee.md) |
| 2023-05-08 | ERC20TokenBank | UncheckedTransfer | [2023-05-08_ERC20TokenBank_UncheckedTransfer.md](./2023-05-08_ERC20TokenBank_UncheckedTransfer.md) |
| 2023-05-09 | LW | ReceiveFunctionUnprotectedSwap | [2023-05-09_LW_ReceiveFunctionUnprotectedSwap.md](./2023-05-09_LW_ReceiveFunctionUnprotectedSwap.md) |
| 2023-05-10 | SNK | RewardCalculation BSC | [2023-05-10_SNK_RewardCalculation_BSC.md](./2023-05-10_SNK_RewardCalculation_BSC.md) |
| 2023-05-12 | CS | StaleGlobalVariable | [2023-05-12_CS_StaleGlobalVariable.md](./2023-05-12_CS_StaleGlobalVariable.md) |
| 2023-05-12 | HODLCapital | ReflectiveDeliver | [2023-05-12_HODLCapital_ReflectiveDeliver.md](./2023-05-12_HODLCapital_ReflectiveDeliver.md) |
| 2023-05-13 | SellToken | PriceDependency BSC | [2023-05-13_SellToken_PriceDependency_BSC.md](./2023-05-13_SellToken_PriceDependency_BSC.md) |
| 2023-05-16 | landNFT | UnrestrictedMint | [2023-05-16_landNFT_UnrestrictedMint.md](./2023-05-16_landNFT_UnrestrictedMint.md) |
| 2023-05-19 | LocalTrader2 | AccessControl | [2023-05-19_LocalTrader2_AccessControl.md](./2023-05-19_LocalTrader2_AccessControl.md) |
| 2023-05-19 | SellToken | PriceOracle | [2023-05-19_SellToken_PriceOracle.md](./2023-05-19_SellToken_PriceOracle.md) |
| 2023-05-21 | MultiChainCapital | DeliverSkimReflection | [2023-05-21_MultiChainCapital_DeliverSkimReflection.md](./2023-05-21_MultiChainCapital_DeliverSkimReflection.md) |
| 2023-05-23 | CSToken | BusinessLogic BSC | [2023-05-23_CSToken_BusinessLogic_BSC.md](./2023-05-23_CSToken_BusinessLogic_BSC.md) |
| 2023-05-24 | GPTToken | FeeMechanism BSC | [2023-05-24_GPTToken_FeeMechanism_BSC.md](./2023-05-24_GPTToken_FeeMechanism_BSC.md) |
| 2023-05-28 | BabyDogeCoin | SlippageProtection BSC | [2023-05-28_BabyDogeCoin_SlippageProtection_BSC.md](./2023-05-28_BabyDogeCoin_SlippageProtection_BSC.md) |
| 2023-05-28 | JimbosProtocol | SlippageExploit ARB | [2023-05-28_JimbosProtocol_SlippageExploit_ARB.md](./2023-05-28_JimbosProtocol_SlippageExploit_ARB.md) |
| 2023-05-31 | ERC20TokenBank | PriceDependency ETH | [2023-05-31_ERC20TokenBank_PriceDependency_ETH.md](./2023-05-31_ERC20TokenBank_PriceDependency_ETH.md) |
| 2023-05-xx | Bitpaidio | StakingLockBypass | [2023-05-xx_Bitpaidio_StakingLockBypass.md](./2023-05-xx_Bitpaidio_StakingLockBypass.md) |
| 2023-05-xx | FAPEN | UnstakeWrongBalanceCheck | [2023-05-xx_FAPEN_UnstakeWrongBalanceCheck.md](./2023-05-xx_FAPEN_UnstakeWrongBalanceCheck.md) |
| 2023-05-xx | LFI | DelegatecallRewardLoop | [2023-05-xx_LFI_DelegatecallRewardLoop.md](./2023-05-xx_LFI_DelegatecallRewardLoop.md) |
| 2023-05-xx | LocalTrader | ProxyStorageSlotManipulation | [2023-05-xx_LocalTrader_ProxyStorageSlotManipulation.md](./2023-05-xx_LocalTrader_ProxyStorageSlotManipulation.md) |
| 2023-05-xx | NOON | TransferVisibilityError | [2023-05-xx_NOON_TransferVisibilityError.md](./2023-05-xx_NOON_TransferVisibilityError.md) |
| 2023-05-xx | NeverFall | BuySellPriceManipulation | [2023-05-xx_NeverFall_BuySellPriceManipulation.md](./2023-05-xx_NeverFall_BuySellPriceManipulation.md) |
| 2023-05-xx | SELLC02 | StakingReferralChainReward | [2023-05-xx_SELLC02_StakingReferralChainReward.md](./2023-05-xx_SELLC02_StakingReferralChainReward.md) |
| 2023-05-xx | SELLC | StakingRewardReferralManipulation | [2023-05-xx_SELLC_StakingRewardReferralManipulation.md](./2023-05-xx_SELLC_StakingRewardReferralManipulation.md) |
| 2023-05-xx | SNK | StakingRewardChildMultiplier | [2023-05-xx_SNK_StakingRewardChildMultiplier.md](./2023-05-xx_SNK_StakingRewardChildMultiplier.md) |
| 2023-06-01 | Cellframe | FlashLoanPriceManipulation | [2023-06-01_Cellframe_FlashLoanPriceManipulation.md](./2023-06-01_Cellframe_FlashLoanPriceManipulation.md) |
| 2023-06-01 | DDCoin | MarketplaceReentrancy | [2023-06-01_DDCoin_MarketplaceReentrancy.md](./2023-06-01_DDCoin_MarketplaceReentrancy.md) |
| 2023-06-05 | NST | SwapPriceArbitrage | [2023-06-05_NST_SwapPriceArbitrage.md](./2023-06-05_NST_SwapPriceArbitrage.md) |
| 2023-06-05 | VINU | AddLiquidityExploit | [2023-06-05_VINU_AddLiquidityExploit.md](./2023-06-05_VINU_AddLiquidityExploit.md) |
| 2023-06-06 | UN | FlashLoanManipulation | [2023-06-06_UN_FlashLoanManipulation.md](./2023-06-06_UN_FlashLoanManipulation.md) |
| 2023-06-07 | Contract | 0x7657 UncheckedTransfer | [2023-06-07_Contract_0x7657_UncheckedTransfer.md](./2023-06-07_Contract_0x7657_UncheckedTransfer.md) |
| 2023-06-07 | UnverifiedContr | AccessControl | [2023-06-07_UnverifiedContr_AccessControl.md](./2023-06-07_UnverifiedContr_AccessControl.md) |
| 2023-06-08 | MyAi | AccessControl | [2023-06-08_MyAi_AccessControl.md](./2023-06-08_MyAi_AccessControl.md) |
| 2023-06-08 | Pawnfi | StakingLogicFlaw | [2023-06-08_Pawnfi_StakingLogicFlaw.md](./2023-06-08_Pawnfi_StakingLogicFlaw.md) |
| 2023-06-08 | STRAC | TokenBurnExploit | [2023-06-08_STRAC_TokenBurnExploit.md](./2023-06-08_STRAC_TokenBurnExploit.md) |
| 2023-06-09 | ARA | FlashLoanPriceManipulation | [2023-06-09_ARA_FlashLoanPriceManipulation.md](./2023-06-09_ARA_FlashLoanPriceManipulation.md) |
| 2023-06-09 | DEPUSDT | LEVUSDC ProxyApproval | [2023-06-09_DEPUSDT_LEVUSDC_ProxyApproval.md](./2023-06-09_DEPUSDT_LEVUSDC_ProxyApproval.md) |
| 2023-06-12 | CFC | FlashLoanManipulation | [2023-06-12_CFC_FlashLoanManipulation.md](./2023-06-12_CFC_FlashLoanManipulation.md) |
| 2023-06-12 | CompounderFinance | ERC4626Inflation | [2023-06-12_CompounderFinance_ERC4626Inflation.md](./2023-06-12_CompounderFinance_ERC4626Inflation.md) |
| 2023-06-12 | SturdyFinance | ReadOnlyReentrancy ETH | [2023-06-12_SturdyFinance_ReadOnlyReentrancy_ETH.md](./2023-06-12_SturdyFinance_ReadOnlyReentrancy_ETH.md) |
| 2023-06-16 | MIMSpell | PriceManipulation | [2023-06-16_MIMSpell_PriceManipulation.md](./2023-06-16_MIMSpell_PriceManipulation.md) |
| 2023-06-17 | BabyDogeCoin02 | FeeLPManipulation | [2023-06-17_BabyDogeCoin02_FeeLPManipulation.md](./2023-06-17_BabyDogeCoin02_FeeLPManipulation.md) |
| 2023-06-17 | MidasCapitalXYZ | PrecisionLoss BSC | [2023-06-17_MidasCapitalXYZ_PrecisionLoss_BSC.md](./2023-06-17_MidasCapitalXYZ_PrecisionLoss_BSC.md) |
| 2023-06-17 | Pawnfi | UntrustedInput ETH | [2023-06-17_Pawnfi_UntrustedInput_ETH.md](./2023-06-17_Pawnfi_UntrustedInput_ETH.md) |
| 2023-06-20 | SELLC03 | ReflectiveSkim3 | [2023-06-20_SELLC03_ReflectiveSkim3.md](./2023-06-20_SELLC03_ReflectiveSkim3.md) |
| 2023-06-22 | BUNN | ReflectiveDeliver | [2023-06-22_BUNN_ReflectiveDeliver.md](./2023-06-22_BUNN_ReflectiveDeliver.md) |
| 2023-06-22 | SHIDO | LockTokenReentrancy | [2023-06-22_SHIDO_LockTokenReentrancy.md](./2023-06-22_SHIDO_LockTokenReentrancy.md) |
| 2023-06-23 | MidasCapitalXYZ | ERC4626InflationBSC | [2023-06-23_MidasCapitalXYZ_ERC4626InflationBSC.md](./2023-06-23_MidasCapitalXYZ_ERC4626InflationBSC.md) |
| 2023-06-23 | Shido | BusinessLogic BSC | [2023-06-23_Shido_BusinessLogic_BSC.md](./2023-06-23_Shido_BusinessLogic_BSC.md) |
| 2023-06-27 | Themis | BalancerGaugePriceManipulation | [2023-06-27_Themis_BalancerGaugePriceManipulation.md](./2023-06-27_Themis_BalancerGaugePriceManipulation.md) |
| 2023-06-29 | Biswap | V3MigrationExploit | [2023-06-29_Biswap_V3MigrationExploit.md](./2023-06-29_Biswap_V3MigrationExploit.md) |
| 2023-06-xx | Contract0x7657 | ArbitraryTransferFrom | [2023-06-xx_Contract0x7657_ArbitraryTransferFrom.md](./2023-06-xx_Contract0x7657_ArbitraryTransferFrom.md) |
| 2023-06-xx | MidasCapital | ReadOnlyReentrancyLP | [2023-06-xx_MidasCapital_ReadOnlyReentrancyLP.md](./2023-06-xx_MidasCapital_ReadOnlyReentrancyLP.md) |
| 2023-06-xx | SHIDO2 | ShidoLockClaimTokens977BNB | [2023-06-xx_SHIDO2_ShidoLockClaimTokens977BNB.md](./2023-06-xx_SHIDO2_ShidoLockClaimTokens977BNB.md) |
| 2023-07-01 | ApeDAO | FlashLoanPriceManipulation | [2023-07-01_ApeDAO_FlashLoanPriceManipulation.md](./2023-07-01_ApeDAO_FlashLoanPriceManipulation.md) |
| 2023-07-01 | AzukiDAO | SignatureReplay | [2023-07-01_AzukiDAO_SignatureReplay.md](./2023-07-01_AzukiDAO_SignatureReplay.md) |
| 2023-07-01 | BNO | FlashLoanReentrancy | [2023-07-01_BNO_FlashLoanReentrancy.md](./2023-07-01_BNO_FlashLoanReentrancy.md) |
| 2023-07-01 | Bamboo | FlashLoanSkim | [2023-07-01_Bamboo_FlashLoanSkim.md](./2023-07-01_Bamboo_FlashLoanSkim.md) |
| 2023-07-01 | Bao | ExchangeRateManipulation | [2023-07-01_Bao_ExchangeRateManipulation.md](./2023-07-01_Bao_ExchangeRateManipulation.md) |
| 2023-07-01 | CIVNFT | AccessControl | [2023-07-01_CIVNFT_AccessControl.md](./2023-07-01_CIVNFT_AccessControl.md) |
| 2023-07-01 | Carson | FlashLoanPriceManipulation | [2023-07-01_Carson_FlashLoanPriceManipulation.md](./2023-07-01_Carson_FlashLoanPriceManipulation.md) |
| 2023-07-01 | Civfund | AccessControl | [2023-07-01_Civfund_AccessControl.md](./2023-07-01_Civfund_AccessControl.md) |
| 2023-07-05 | GYMNET | FlashLoanLiquidity | [2023-07-05_GYMNET_FlashLoanLiquidity.md](./2023-07-05_GYMNET_FlashLoanLiquidity.md) |
| 2023-07-08 | CIVNFT | AccessControl ETH | [2023-07-08_CIVNFT_AccessControl_ETH.md](./2023-07-08_CIVNFT_AccessControl_ETH.md) |
| 2023-07-10 | ArcadiaFinance | Reentrancy ETH | [2023-07-10_ArcadiaFinance_Reentrancy_ETH.md](./2023-07-10_ArcadiaFinance_Reentrancy_ETH.md) |
| 2023-07-10 | LUSD | FlashLoanOracle | [2023-07-10_LUSD_FlashLoanOracle.md](./2023-07-10_LUSD_FlashLoanOracle.md) |
| 2023-07-10 | MintoFinance | SignatureBypass | [2023-07-10_MintoFinance_SignatureBypass.md](./2023-07-10_MintoFinance_SignatureBypass.md) |
| 2023-07-10 | NewFi | FlashLoanCascade | [2023-07-10_NewFi_FlashLoanCascade.md](./2023-07-10_NewFi_FlashLoanCascade.md) |
| 2023-07-10 | USDTStakingContract28 | AccessControl | [2023-07-10_USDTStakingContract28_AccessControl.md](./2023-07-10_USDTStakingContract28_AccessControl.md) |
| 2023-07-11 | Libertify | Reentrancy ETH | [2023-07-11_Libertify_Reentrancy_ETH.md](./2023-07-11_Libertify_Reentrancy_ETH.md) |
| 2023-07-11 | RodeoFinance | TWAPOracleManipulation ARB | [2023-07-11_RodeoFinance_TWAPOracleManipulation_ARB.md](./2023-07-11_RodeoFinance_TWAPOracleManipulation_ARB.md) |
| 2023-07-14 | Palmswap | ExchangeRateManipulation | [2023-07-14_Palmswap_ExchangeRateManipulation.md](./2023-07-14_Palmswap_ExchangeRateManipulation.md) |
| 2023-07-16 | USDTStaking | Approval | [2023-07-16_USDTStaking_Approval.md](./2023-07-16_USDTStaking_Approval.md) |
| 2023-07-18 | Libertify | Reentrancy | [2023-07-18_Libertify_Reentrancy.md](./2023-07-18_Libertify_Reentrancy.md) |
| 2023-07-19 | SUT | FlashLoanPriceManipulation | [2023-07-19_SUT_FlashLoanPriceManipulation.md](./2023-07-19_SUT_FlashLoanPriceManipulation.md) |
| 2023-07-20 | FFISTToken | BusinessLogic BSC | [2023-07-20_FFISTToken_BusinessLogic_BSC.md](./2023-07-20_FFISTToken_BusinessLogic_BSC.md) |
| 2023-07-21 | ConicFinance | ReadOnlyReentrancy ETH | [2023-07-21_ConicFinance_ReadOnlyReentrancy_ETH.md](./2023-07-21_ConicFinance_ReadOnlyReentrancy_ETH.md) |
| 2023-07-21 | FFIST | ReserveManipulation | [2023-07-21_FFIST_ReserveManipulation.md](./2023-07-21_FFIST_ReserveManipulation.md) |
| 2023-07-21 | RodeoFinance | TWAPManipulation | [2023-07-21_RodeoFinance_TWAPManipulation.md](./2023-07-21_RodeoFinance_TWAPManipulation.md) |
| 2023-07-24 | Palmswap | OracleManipulation BSC | [2023-07-24_Palmswap_OracleManipulation_BSC.md](./2023-07-24_Palmswap_OracleManipulation_BSC.md) |
| 2023-07-25 | Platypus02 | PriceManipulation | [2023-07-25_Platypus02_PriceManipulation.md](./2023-07-25_Platypus02_PriceManipulation.md) |
| 2023-07-26 | CarsonToken | PriceDependency BSC | [2023-07-26_CarsonToken_PriceDependency_BSC.md](./2023-07-26_CarsonToken_PriceDependency_BSC.md) |
| 2023-07-28 | Utopia | BusinessLogicFlaw | [2023-07-28_Utopia_BusinessLogicFlaw.md](./2023-07-28_Utopia_BusinessLogicFlaw.md) |
| 2023-07-30 | Conic | ReadOnlyReentrancy | [2023-07-30_Conic_ReadOnlyReentrancy.md](./2023-07-30_Conic_ReadOnlyReentrancy.md) |
| 2023-07-30 | Curve | VyperReentrancy ETH | [2023-07-30_Curve_VyperReentrancy_ETH.md](./2023-07-30_Curve_VyperReentrancy_ETH.md) |
| 2023-07-31 | WGPT | FlashLoanTokenBurn | [2023-07-31_WGPT_FlashLoanTokenBurn.md](./2023-07-31_WGPT_FlashLoanTokenBurn.md) |
| 2023-08-01 | Balancer | PrecisionLoss | [2023-08-01_Balancer_PrecisionLoss.md](./2023-08-01_Balancer_PrecisionLoss.md) |
| 2023-08-01 | LeetSwap | AccessControl Base | [2023-08-01_LeetSwap_AccessControl_Base.md](./2023-08-01_LeetSwap_AccessControl_Base.md) |
| 2023-08-03 | MEVBot | 0xd61492 UnverifiedInput ARB | [2023-08-03_MEVBot_0xd61492_UnverifiedInput_ARB.md](./2023-08-03_MEVBot_0xd61492_UnverifiedInput_ARB.md) |
| 2023-08-08 | BTC20 | PresalePriceManipulation | [2023-08-08_BTC20_PresalePriceManipulation.md](./2023-08-08_BTC20_PresalePriceManipulation.md) |
| 2023-08-09 | EarningFarm | Reentrancy ETH | [2023-08-09_EarningFarm_Reentrancy_ETH.md](./2023-08-09_EarningFarm_Reentrancy_ETH.md) |
| 2023-08-13 | Zunami | CurveSpotPriceManipulation ETH | [2023-08-13_Zunami_CurveSpotPriceManipulation_ETH.md](./2023-08-13_Zunami_CurveSpotPriceManipulation_ETH.md) |
| 2023-08-16 | EAC | FlashLoanProxy | [2023-08-16_EAC_FlashLoanProxy.md](./2023-08-16_EAC_FlashLoanProxy.md) |
| 2023-08-17 | Exactly | CollateralManipulation | [2023-08-17_Exactly_CollateralManipulation.md](./2023-08-17_Exactly_CollateralManipulation.md) |
| 2023-08-18 | ExactlyProtocol | PeripheralAccessControl OP | [2023-08-18_ExactlyProtocol_PeripheralAccessControl_OP.md](./2023-08-18_ExactlyProtocol_PeripheralAccessControl_OP.md) |
| 2023-08-21 | NeutraFinance | FlashLoan | [2023-08-21_NeutraFinance_FlashLoan.md](./2023-08-21_NeutraFinance_FlashLoan.md) |
| 2023-08-22 | CurveBurner | SandwichAttack | [2023-08-22_CurveBurner_SandwichAttack.md](./2023-08-22_CurveBurner_SandwichAttack.md) |
| 2023-08-22 | Zunami | PriceManipulation | [2023-08-22_Zunami_PriceManipulation.md](./2023-08-22_Zunami_PriceManipulation.md) |
| 2023-08-26 | SVT | FlawedPriceCalc BSC | [2023-08-26_SVT_FlawedPriceCalc_BSC.md](./2023-08-26_SVT_FlawedPriceCalc_BSC.md) |
| 2023-08-27 | Balancer | BoostedPoolVuln ETH | [2023-08-27_Balancer_BoostedPoolVuln_ETH.md](./2023-08-27_Balancer_BoostedPoolVuln_ETH.md) |
| 2023-08-28 | EHIVE | StakingOrderManipulation | [2023-08-28_EHIVE_StakingOrderManipulation.md](./2023-08-28_EHIVE_StakingOrderManipulation.md) |
| 2023-08-28 | EarningFarm | Reentrancy | [2023-08-28_EarningFarm_Reentrancy.md](./2023-08-28_EarningFarm_Reentrancy.md) |
| 2023-08-28 | GSS | FlashLoanSkimSync | [2023-08-28_GSS_FlashLoanSkimSync.md](./2023-08-28_GSS_FlashLoanSkimSync.md) |
| 2023-08-28 | Leetswap | FeeManipulation | [2023-08-28_Leetswap_FeeManipulation.md](./2023-08-28_Leetswap_FeeManipulation.md) |
| 2023-08-30 | Uwerx | TokenLogic | [2023-08-30_Uwerx_TokenLogic.md](./2023-08-30_Uwerx_TokenLogic.md) |
| 2023-08-31 | SVT | PriceManipulation | [2023-08-31_SVT_PriceManipulation.md](./2023-08-31_SVT_PriceManipulation.md) |
| 2023-09-01 | DEXRouter | ArbitraryCall | [2023-09-01_DEXRouter_ArbitraryCall.md](./2023-09-01_DEXRouter_ArbitraryCall.md) |
| 2023-09-01 | HeavensGate | TokenLogic | [2023-09-01_HeavensGate_TokenLogic.md](./2023-09-01_HeavensGate_TokenLogic.md) |
| 2023-09-05 | JumpFarm | Staking | [2023-09-05_JumpFarm_Staking.md](./2023-09-05_JumpFarm_Staking.md) |
| 2023-09-05 | QuantumWN | Staking | [2023-09-05_QuantumWN_Staking.md](./2023-09-05_QuantumWN_Staking.md) |
| 2023-09-07 | 0x0DEX | AccessControl | [2023-09-07_0x0DEX_AccessControl.md](./2023-09-07_0x0DEX_AccessControl.md) |
| 2023-09-07 | DAppSocial | Reentrancy | [2023-09-07_DAppSocial_Reentrancy.md](./2023-09-07_DAppSocial_Reentrancy.md) |
| 2023-09-08 | HCT | FlashLoanBurn | [2023-09-08_HCT_FlashLoanBurn.md](./2023-09-08_HCT_FlashLoanBurn.md) |
| 2023-09-11 | APIG | FlashLoan | [2023-09-11_APIG_FlashLoan.md](./2023-09-11_APIG_FlashLoan.md) |
| 2023-09-11 | BFCToken | FlashLoan | [2023-09-11_BFCToken_FlashLoan.md](./2023-09-11_BFCToken_FlashLoan.md) |
| 2023-09-12 | uniclyNFT | Reentrancy | [2023-09-12_uniclyNFT_Reentrancy.md](./2023-09-12_uniclyNFT_Reentrancy.md) |
| 2023-09-15 | FloorDAO | StakingRebase | [2023-09-15_FloorDAO_StakingRebase.md](./2023-09-15_FloorDAO_StakingRebase.md) |
| 2023-09-20 | Kub | Split StakingArbitrage | [2023-09-20_Kub_Split_StakingArbitrage.md](./2023-09-20_Kub_Split_StakingArbitrage.md) |
| 2023-09-20 | XSDWETHpool | PIDManipulation | [2023-09-20_XSDWETHpool_PIDManipulation.md](./2023-09-20_XSDWETHpool_PIDManipulation.md) |
| 2023-09-21 | CEXISWAP | AccessControl | [2023-09-21_CEXISWAP_AccessControl.md](./2023-09-21_CEXISWAP_AccessControl.md) |
| 2023-09-21 | KubSplit | AccessControl | [2023-09-21_KubSplit_AccessControl.md](./2023-09-21_KubSplit_AccessControl.md) |
| 2023-09-23 | StarsArena | Reentrancy AVAX | [2023-09-23_StarsArena_Reentrancy_AVAX.md](./2023-09-23_StarsArena_Reentrancy_AVAX.md) |
| 2023-09-26 | FireBirdPair | Reentrancy | [2023-09-26_FireBirdPair_Reentrancy.md](./2023-09-26_FireBirdPair_Reentrancy.md) |
| 2023-10-03 | MaestroRouter2 | TransferFrom | [2023-10-03_MaestroRouter2_TransferFrom.md](./2023-10-03_MaestroRouter2_TransferFrom.md) |
| 2023-10-04 | StarsArena | Reentrancy | [2023-10-04_StarsArena_Reentrancy.md](./2023-10-04_StarsArena_Reentrancy.md) |
| 2023-10-05 | DePayRouter | CallInjection | [2023-10-05_DePayRouter_CallInjection.md](./2023-10-05_DePayRouter_CallInjection.md) |
| 2023-10-11 | Astrid | WithdrawExploit | [2023-10-11_Astrid_WithdrawExploit.md](./2023-10-11_Astrid_WithdrawExploit.md) |
| 2023-10-11 | BHToken | BusinessLogic BSC | [2023-10-11_BHToken_BusinessLogic_BSC.md](./2023-10-11_BHToken_BusinessLogic_BSC.md) |
| 2023-10-12 | Platypus | EmergencyWithdraw AVAX | [2023-10-12_Platypus_EmergencyWithdraw_AVAX.md](./2023-10-12_Platypus_EmergencyWithdraw_AVAX.md) |
| 2023-10-16 | OpenLeverage | AdminTakeover | [2023-10-16_OpenLeverage_AdminTakeover.md](./2023-10-16_OpenLeverage_AdminTakeover.md) |
| 2023-10-16 | Platypus03 | FlashLoanLP | [2023-10-16_Platypus03_FlashLoanLP.md](./2023-10-16_Platypus03_FlashLoanLP.md) |
| 2023-10-18 | BH | FlashLoanLiquidity | [2023-10-18_BH_FlashLoanLiquidity.md](./2023-10-18_BH_FlashLoanLiquidity.md) |
| 2023-10-18 | BelugaDex | FlashLoan | [2023-10-18_BelugaDex_FlashLoan.md](./2023-10-18_BelugaDex_FlashLoan.md) |
| 2023-10-18 | HopeMoney | PrecisionLoss ETH | [2023-10-18_HopeMoney_PrecisionLoss_ETH.md](./2023-10-18_HopeMoney_PrecisionLoss_ETH.md) |
| 2023-10-18 | MicDao | HelperContractArbitrage | [2023-10-18_MicDao_HelperContractArbitrage.md](./2023-10-18_MicDao_HelperContractArbitrage.md) |
| 2023-10-22 | UniBot | UnauthorizedTransfer | [2023-10-22_UniBot_UnauthorizedTransfer.md](./2023-10-22_UniBot_UnauthorizedTransfer.md) |
| 2023-10-24 | Maestro | ArbitraryCall ETH | [2023-10-24_Maestro_ArbitraryCall_ETH.md](./2023-10-24_Maestro_ArbitraryCall_ETH.md) |
| 2023-10-26 | LaEeb | FlashLoan | [2023-10-26_LaEeb_FlashLoan.md](./2023-10-26_LaEeb_FlashLoan.md) |
| 2023-10-26 | WiseLending | PrecisionLoss | [2023-10-26_WiseLending_PrecisionLoss.md](./2023-10-26_WiseLending_PrecisionLoss.md) |
| 2023-10-28 | AstridFinance | BusinessLogic ETH | [2023-10-28_AstridFinance_BusinessLogic_ETH.md](./2023-10-28_AstridFinance_BusinessLogic_ETH.md) |
| 2023-10-31 | ZS | FlashLoanSkimSync | [2023-10-31_ZS_FlashLoanSkimSync.md](./2023-10-31_ZS_FlashLoanSkimSync.md) |
| 2023-10-31 | kTAF | FlashLoanLiquidation | [2023-10-31_kTAF_FlashLoanLiquidation.md](./2023-10-31_kTAF_FlashLoanLiquidation.md) |
| 2023-10-31 | pSeudoEth | SkimArbitrage | [2023-10-31_pSeudoEth_SkimArbitrage.md](./2023-10-31_pSeudoEth_SkimArbitrage.md) |
| 2023-11-01 | 3913 | FlashLoanBurnPairs | [2023-11-01_3913_FlashLoanBurnPairs.md](./2023-11-01_3913_FlashLoanBurnPairs.md) |
| 2023-11-01 | OnyxProtocol | ERC4626Inflation ETH | [2023-11-01_OnyxProtocol_ERC4626Inflation_ETH.md](./2023-11-01_OnyxProtocol_ERC4626Inflation_ETH.md) |
| 2023-11-02 | AIS | AccessControl | [2023-11-02_AIS_AccessControl.md](./2023-11-02_AIS_AccessControl.md) |
| 2023-11-05 | BRAND | FlashLoanBuyToken | [2023-11-05_BRAND_FlashLoanBuyToken.md](./2023-11-05_BRAND_FlashLoanBuyToken.md) |
| 2023-11-06 | Burntbubba | EmergencyWithdraw | [2023-11-06_Burntbubba_EmergencyWithdraw.md](./2023-11-06_Burntbubba_EmergencyWithdraw.md) |
| 2023-11-06 | TheStandard | SlippageProtection ARB | [2023-11-06_TheStandard_SlippageProtection_ARB.md](./2023-11-06_TheStandard_SlippageProtection_ARB.md) |
| 2023-11-06 | bot | SmartVault | [2023-11-06_bot_SmartVault.md](./2023-11-06_bot_SmartVault.md) |
| 2023-11-07 | CAROLProtocol | Reentrancy | [2023-11-07_CAROLProtocol_Reentrancy.md](./2023-11-07_CAROLProtocol_Reentrancy.md) |
| 2023-11-07 | MEVBot | AccessControl ETH | [2023-11-07_MEVBot_AccessControl_ETH.md](./2023-11-07_MEVBot_AccessControl_ETH.md) |
| 2023-11-07 | XAI | TokenLogic | [2023-11-07_XAI_TokenLogic.md](./2023-11-07_XAI_TokenLogic.md) |
| 2023-11-08 | EEE | PriceManipulation | [2023-11-08_EEE_PriceManipulation.md](./2023-11-08_EEE_PriceManipulation.md) |
| 2023-11-08 | KR | TokenSell | [2023-11-08_KR_TokenSell.md](./2023-11-08_KR_TokenSell.md) |
| 2023-11-09 | TrustPad | FlashLoan | [2023-11-09_TrustPad_FlashLoan.md](./2023-11-09_TrustPad_FlashLoan.md) |
| 2023-11-10 | EHX | FlashLoanSkim | [2023-11-10_EHX_FlashLoanSkim.md](./2023-11-10_EHX_FlashLoanSkim.md) |
| 2023-11-10 | Raft | FlashMintPrecision ETH | [2023-11-10_Raft_FlashMintPrecision_ETH.md](./2023-11-10_Raft_FlashMintPrecision_ETH.md) |
| 2023-11-12 | FiberRouter | CalldataInjection | [2023-11-12_FiberRouter_CalldataInjection.md](./2023-11-12_FiberRouter_CalldataInjection.md) |
| 2023-11-12 | MEVBot | 0x8c2d4e AccessControl BSC | [2023-11-12_MEVBot_0x8c2d4e_AccessControl_BSC.md](./2023-11-12_MEVBot_0x8c2d4e_AccessControl_BSC.md) |
| 2023-11-13 | Token8633 | FlashLoan | [2023-11-13_Token8633_FlashLoan.md](./2023-11-13_Token8633_FlashLoan.md) |
| 2023-11-13 | grok | FlashLoan | [2023-11-13_grok_FlashLoan.md](./2023-11-13_grok_FlashLoan.md) |
| 2023-11-14 | MahaLend | CompoundFork | [2023-11-14_MahaLend_CompoundFork.md](./2023-11-14_MahaLend_CompoundFork.md) |
| 2023-11-15 | KyberSwap | TickManipulation | [2023-11-15_KyberSwap_TickManipulation.md](./2023-11-15_KyberSwap_TickManipulation.md) |
| 2023-11-16 | LinkDao | FlashSwapReentrancy | [2023-11-16_LinkDao_FlashSwapReentrancy.md](./2023-11-16_LinkDao_FlashSwapReentrancy.md) |
| 2023-11-18 | MEV | 0x8c2d AccessControl | [2023-11-18_MEV_0x8c2d_AccessControl.md](./2023-11-18_MEV_0x8c2d_AccessControl.md) |
| 2023-11-20 | OnyxProtocol | PrecisionLoss | [2023-11-20_OnyxProtocol_PrecisionLoss.md](./2023-11-20_OnyxProtocol_PrecisionLoss.md) |
| 2023-11-21 | Raft | PrecisionLoss | [2023-11-21_Raft_PrecisionLoss.md](./2023-11-21_Raft_PrecisionLoss.md) |
| 2023-11-22 | KyberSwap | TickMathBug Multi | [2023-11-22_KyberSwap_TickMathBug_Multi.md](./2023-11-22_KyberSwap_TickMathBug_Multi.md) |
| 2023-11-22 | RBalancer | FlashLoan | [2023-11-22_RBalancer_FlashLoan.md](./2023-11-22_RBalancer_FlashLoan.md) |
| 2023-11-23 | OKC | FlashLoanLPReward | [2023-11-23_OKC_FlashLoanLPReward.md](./2023-11-23_OKC_FlashLoanLPReward.md) |
| 2023-11-24 | MetaLend | CompoundFork | [2023-11-24_MetaLend_CompoundFork.md](./2023-11-24_MetaLend_CompoundFork.md) |
| 2023-11-24 | WECO | TokenLogic | [2023-11-24_WECO_TokenLogic.md](./2023-11-24_WECO_TokenLogic.md) |
| 2023-11-27 | ShibaToken | AccessControl | [2023-11-27_ShibaToken_AccessControl.md](./2023-11-27_ShibaToken_AccessControl.md) |
| 2023-11-28 | SwampFinance | FlashLoan | [2023-11-28_SwampFinance_FlashLoan.md](./2023-11-28_SwampFinance_FlashLoan.md) |
| 2023-11-29 | TheNFTV2 | Reentrancy | [2023-11-29_TheNFTV2_Reentrancy.md](./2023-11-29_TheNFTV2_Reentrancy.md) |
| 2023-11-30 | TheStandard | io PriceManipulation | [2023-11-30_TheStandard_io_PriceManipulation.md](./2023-11-30_TheStandard_io_PriceManipulation.md) |
| 2023-12-01 | BEARNDAO | BusinessLogic | [2023-12-01_BEARNDAO_BusinessLogic.md](./2023-12-01_BEARNDAO_BusinessLogic.md) |
| 2023-12-01 | Bob | RouterExploit | [2023-12-01_Bob_RouterExploit.md](./2023-12-01_Bob_RouterExploit.md) |
| 2023-12-03 | ElephantStatus | Reentrancy | [2023-12-03_ElephantStatus_Reentrancy.md](./2023-12-03_ElephantStatus_Reentrancy.md) |
| 2023-12-05 | BCT | TokenLogic | [2023-12-05_BCT_TokenLogic.md](./2023-12-05_BCT_TokenLogic.md) |
| 2023-12-05 | BEARNDAO | SlippageProtection BSC | [2023-12-05_BEARNDAO_SlippageProtection_BSC.md](./2023-12-05_BEARNDAO_SlippageProtection_BSC.md) |
| 2023-12-05 | CCV | FlashLoan | [2023-12-05_CCV_FlashLoan.md](./2023-12-05_CCV_FlashLoan.md) |
| 2023-12-05 | PHIL | TokenSellExploit | [2023-12-05_PHIL_TokenSellExploit.md](./2023-12-05_PHIL_TokenSellExploit.md) |
| 2023-12-06 | ElephantMoney | PriceDependency BSC | [2023-12-06_ElephantMoney_PriceDependency_BSC.md](./2023-12-06_ElephantMoney_PriceDependency_BSC.md) |
| 2023-12-12 | DominoTT | PriceManipulation | [2023-12-12_DominoTT_PriceManipulation.md](./2023-12-12_DominoTT_PriceManipulation.md) |
| 2023-12-12 | HNet | PriceManipulation | [2023-12-12_HNet_PriceManipulation.md](./2023-12-12_HNet_PriceManipulation.md) |
| 2023-12-13 | HyprNetwork | BusinessLogic ETH | [2023-12-13_HyprNetwork_BusinessLogic_ETH.md](./2023-12-13_HyprNetwork_BusinessLogic_ETH.md) |
| 2023-12-14 | HYPR | ProxyExploit | [2023-12-14_HYPR_ProxyExploit.md](./2023-12-14_HYPR_ProxyExploit.md) |
| 2023-12-14 | KEST | FlashLoan | [2023-12-14_KEST_FlashLoan.md](./2023-12-14_KEST_FlashLoan.md) |
| 2023-12-14 | bZx | LoanExploit | [2023-12-14_bZx_LoanExploit.md](./2023-12-14_bZx_LoanExploit.md) |
| 2023-12-16 | FloorProtocol | NFTExploit | [2023-12-16_FloorProtocol_NFTExploit.md](./2023-12-16_FloorProtocol_NFTExploit.md) |
| 2023-12-16 | GoodDollar | ReserveExploit | [2023-12-16_GoodDollar_ReserveExploit.md](./2023-12-16_GoodDollar_ReserveExploit.md) |
| 2023-12-16 | NFTTrader | Reentrancy ETH | [2023-12-16_NFTTrader_Reentrancy_ETH.md](./2023-12-16_NFTTrader_Reentrancy_ETH.md) |
| 2023-12-16 | TransitFinance | CallInjection | [2023-12-16_TransitFinance_CallInjection.md](./2023-12-16_TransitFinance_CallInjection.md) |
| 2023-12-17 | FloorProtocol | BusinessLogic ETH | [2023-12-17_FloorProtocol_BusinessLogic_ETH.md](./2023-12-17_FloorProtocol_BusinessLogic_ETH.md) |
| 2023-12-17 | GoodCompound | GovernanceExploit | [2023-12-17_GoodCompound_GovernanceExploit.md](./2023-12-17_GoodCompound_GovernanceExploit.md) |
| 2023-12-17 | PineProtocol | NFTLoanExploit | [2023-12-17_PineProtocol_NFTLoanExploit.md](./2023-12-17_PineProtocol_NFTLoanExploit.md) |
| 2023-12-19 | Channels | CompoundFork | [2023-12-19_Channels_CompoundFork.md](./2023-12-19_Channels_CompoundFork.md) |
| 2023-12-20 | TransitFinance | UntrustedInput BSC | [2023-12-20_TransitFinance_UntrustedInput_BSC.md](./2023-12-20_TransitFinance_UntrustedInput_BSC.md) |
| 2023-12-25 | MAMO | TokenLogic | [2023-12-25_MAMO_TokenLogic.md](./2023-12-25_MAMO_TokenLogic.md) |
| 2023-12-26 | TIME | ERC2771Exploit | [2023-12-26_TIME_ERC2771Exploit.md](./2023-12-26_TIME_ERC2771Exploit.md) |
| 2023-12-26 | Telcoin | ProxyStorageCollision | [2023-12-26_Telcoin_ProxyStorageCollision.md](./2023-12-26_Telcoin_ProxyStorageCollision.md) |
| 2023-12-29 | ChannelsFinance | DonationAttack | [2023-12-29_ChannelsFinance_DonationAttack.md](./2023-12-29_ChannelsFinance_DonationAttack.md) |

---

[← Back to main index](../README.md)
