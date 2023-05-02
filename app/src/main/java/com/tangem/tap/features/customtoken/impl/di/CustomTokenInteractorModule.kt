package com.tangem.tap.features.customtoken.impl.di

import com.tangem.datasource.api.tangemTech.TangemTechApi
import com.tangem.lib.crypto.DerivationManager
import com.tangem.tap.features.customtoken.impl.data.DefaultCustomTokenRepository
import com.tangem.tap.features.customtoken.impl.domain.CustomTokenInteractor
import com.tangem.tap.features.customtoken.impl.domain.DefaultCustomTokenInteractor
import com.tangem.tap.proxy.AppStateHolder
import com.tangem.utils.coroutines.AppCoroutineDispatcherProvider
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ViewModelComponent
import dagger.hilt.android.scopes.ViewModelScoped

/**
 * @author Andrew Khokhlov on 25/04/2023
 */
@Module
@InstallIn(ViewModelComponent::class)
internal object CustomTokenInteractorModule {

    @Provides
    @ViewModelScoped
    fun provideCustomTokenInteractor(
        tangemTechApi: TangemTechApi,
        appCoroutineDispatcherProvider: AppCoroutineDispatcherProvider,
        reduxStateHolder: AppStateHolder,
        derivationManager: DerivationManager,
    ): CustomTokenInteractor {
        return DefaultCustomTokenInteractor(
            featureRepository = DefaultCustomTokenRepository(
                tangemTechApi = tangemTechApi,
                dispatchers = appCoroutineDispatcherProvider,
                reduxStateHolder = reduxStateHolder,
            ),
            derivationManager = derivationManager,
            reduxStateHolder = reduxStateHolder,
        )
    }
}
