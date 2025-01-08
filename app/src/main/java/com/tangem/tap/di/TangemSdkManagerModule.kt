package com.tangem.tap.di

import android.content.Context
import com.tangem.domain.card.BuildConfig
import com.tangem.domain.card.repository.CardSdkConfigRepository
import com.tangem.domain.visa.repository.VisaAuthRepository
import com.tangem.sdk.api.TangemSdkManager
import com.tangem.tap.domain.sdk.impl.DefaultTangemSdkManager
import com.tangem.tap.domain.sdk.impl.MockTangemSdkManager
import com.tangem.tap.domain.visa.VisaCardScanHandler
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
class TangemSdkManagerModule {

    @Provides
    @Singleton
    internal fun provideTangemSdkManager(
        @ApplicationContext context: Context,
        cardSdkConfigRepository: CardSdkConfigRepository,
        visaCardScanHandler: VisaCardScanHandler,
    ): TangemSdkManager {
        return if (BuildConfig.MOCK_DATA_SOURCE) {
            MockTangemSdkManager(resources = context.resources)
        } else {
            DefaultTangemSdkManager(
                cardSdkConfigRepository = cardSdkConfigRepository,
                resources = context.resources,
                visaCardScanHandler = visaCardScanHandler,
            )
        }
    }

    @Provides
    @Singleton
    internal fun provideVisaCardScanHandler(visaAuthRepository: VisaAuthRepository): VisaCardScanHandler {
        return VisaCardScanHandler(
            visaAuthRepository = visaAuthRepository,
            coroutineScope = CoroutineScope(Dispatchers.Main),
        )
    }
}
