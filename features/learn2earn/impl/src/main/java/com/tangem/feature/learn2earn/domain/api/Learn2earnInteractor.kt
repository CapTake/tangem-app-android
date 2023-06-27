package com.tangem.feature.learn2earn.domain.api

import android.net.Uri

/**
 * @author Anton Zhilenkov on 07.06.2023.
 */
interface Learn2earnInteractor : WebViewRedirectHandler {

    var webViewResultHandler: WebViewResultHandler?

    fun setupDependencies(authCredentials: String?, countryCodeProvider: () -> String)

    suspend fun init()

    fun isUserHadPromoCode(): Boolean

    fun isNeedToShowViewOnStoriesScreen(): Boolean

    suspend fun isNeedToShowViewOnMainScreen(): Boolean

    fun isUserRegisteredInPromotion(): Boolean

    fun getAwardAmount(): Int

    @Throws(IllegalArgumentException::class)
    suspend fun requestAward(): Result<Unit>

    fun buildUriForNewUser(): Uri

    fun buildUriForOldUser(): Uri

    fun getBasicAuthHeaders(): ArrayList<String>
}
