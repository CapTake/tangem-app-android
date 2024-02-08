package com.tangem.feature.wallet.presentation.wallet.subscribers

import com.tangem.domain.wallets.models.UserWalletId
import com.tangem.feature.wallet.presentation.wallet.analytics.utils.WalletWarningsAnalyticsSender
import com.tangem.feature.wallet.presentation.wallet.domain.GetSingleWalletWarningsFactory
import com.tangem.feature.wallet.presentation.wallet.state.components.WalletNotification
import com.tangem.feature.wallet.presentation.wallet.state2.WalletStateController
import com.tangem.feature.wallet.presentation.wallet.state2.transformers.SetWarningsTransformer
import com.tangem.feature.wallet.presentation.wallet.viewmodels.intents.WalletClickIntentsV2
import kotlinx.collections.immutable.ImmutableList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.onEach

/**
 * @author Andrew Khokhlov on 16/11/2023
 */
internal class SingleWalletNotificationsSubscriber(
    private val userWalletId: UserWalletId,
    private val stateHolder: WalletStateController,
    private val getSingleWalletWarningsFactory: GetSingleWalletWarningsFactory,
    private val walletWarningsAnalyticsSender: WalletWarningsAnalyticsSender,
    private val clickIntents: WalletClickIntentsV2,
) : WalletSubscriber() {

    override fun create(coroutineScope: CoroutineScope): Flow<ImmutableList<WalletNotification>> {
        return getSingleWalletWarningsFactory.create(clickIntents)
            .conflate()
            .distinctUntilChanged()
            .onEach { warnings ->
                val displayedState = stateHolder.getWalletState(userWalletId)

                stateHolder.update(SetWarningsTransformer(userWalletId, warnings))
                walletWarningsAnalyticsSender.send(displayedState, warnings)
            }
    }
}
