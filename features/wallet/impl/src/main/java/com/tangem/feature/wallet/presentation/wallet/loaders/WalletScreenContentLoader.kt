package com.tangem.feature.wallet.presentation.wallet.loaders

import com.tangem.domain.appcurrency.model.AppCurrency
import com.tangem.domain.wallets.models.UserWallet
import com.tangem.domain.wallets.models.UserWalletId
import com.tangem.feature.wallet.presentation.wallet.viewmodels.intents.WalletClickIntentsV2
import com.tangem.utils.coroutines.CoroutineDispatcherProvider
import dagger.hilt.android.scopes.ViewModelScoped
import kotlinx.coroutines.CoroutineScope
import timber.log.Timber
import javax.inject.Inject

/**
 * Base wallet screen content loader. Use it to load content by [UserWallet].
 *
 * @property factory     factory that creates loader
 * @property storage     storage that save loader's jobs
 * @property dispatchers coroutine dispatchers provider
 *
 * @author Andrew Khokhlov on 24/11/2023
 */
@ViewModelScoped
internal class WalletScreenContentLoader @Inject constructor(
    private val factory: WalletContentLoaderFactory,
    private val storage: WalletLoaderStorage,
    private val dispatchers: CoroutineDispatcherProvider,
) {

    /**
     * Load content by [UserWallet]
     *
     * @param userWallet     user wallet
     * @param appCurrency    app currency
     * @param clickIntents   click intents
     * @param isRefresh      flag that determinate if content must load again
     * @param coroutineScope coroutine scope
     */
    fun load(
        userWallet: UserWallet,
        appCurrency: AppCurrency,
        clickIntents: WalletClickIntentsV2,
        isRefresh: Boolean = false,
        coroutineScope: CoroutineScope,
    ) {
        if (userWallet.isLocked) return

        val id = userWallet.walletId
        if (!storage.contains(id)) {
            loadInternal(userWallet, appCurrency, clickIntents, coroutineScope, isRefresh)
        } else {
            if (isRefresh) {
                storage.remove(id)
                loadInternal(userWallet, appCurrency, clickIntents, coroutineScope, true)
            } else {
                Timber.d("$id content loading has already started")
            }
        }
    }

    /** Cancel loading by [id] */
    fun cancel(id: UserWalletId) {
        Timber.d("$id content loading is canceled")
        storage.remove(id)
    }

    private fun loadInternal(
        userWallet: UserWallet,
        appCurrency: AppCurrency,
        clickIntents: WalletClickIntentsV2,
        coroutineScope: CoroutineScope,
        isRefresh: Boolean,
    ) {
        val loader = factory.create(
            userWallet = userWallet,
            appCurrency = appCurrency,
            clickIntents = clickIntents,
            isRefresh = isRefresh,
        )

        if (loader == null) {
            Timber.e("Impossible to create loader for $userWallet")
            return
        }

        Timber.d("${userWallet.walletId} content loading is ${if (isRefresh) "re" else ""}started")

        loader.subscribers
            .map { it.subscribe(coroutineScope, dispatchers) }
            .let { storage.set(userWallet.walletId, it) }
    }
}
