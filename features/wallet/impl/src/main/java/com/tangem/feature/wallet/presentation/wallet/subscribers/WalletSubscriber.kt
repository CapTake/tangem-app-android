package com.tangem.feature.wallet.presentation.wallet.subscribers

import com.tangem.utils.coroutines.CoroutineDispatcherProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.launchIn
import timber.log.Timber
import kotlin.coroutines.CoroutineContext

/**
 * @author Andrew Khokhlov on 16/11/2023
 */
internal abstract class WalletSubscriber<T>(val name: String) {

    protected abstract fun create(coroutineScope: CoroutineScope, uiDispatcher: CoroutineContext): Flow<T>

    fun subscribe(coroutineScope: CoroutineScope, dispatchers: CoroutineDispatcherProvider): Job {
        Timber.d("Subscribe on $name")
        return create(coroutineScope, dispatchers.main)
            .flowOn(dispatchers.main)
            .launchIn(coroutineScope)
    }
}
