package com.tangem.feature.learn2earn.domain.api

import com.tangem.core.analytics.models.AnalyticsEvent

/**
 * Handler that helps determine a result of the Learn2earnWebViewActivity webView actions.
 *
 * @author Anton Zhilenkov on 23.06.2023.
 */
interface WebViewResultHandler {
    fun handleResult(result: WebViewResult)
}

sealed class WebViewResult {

    object Empty : WebViewResult()

    data class NewUserLearningFinished(val promoCode: String?) : WebViewResult()

    object OldUserLearningFinished : WebViewResult()

    object ReadyForAward : WebViewResult()

    data class Learn2earnAnalyticsEvent(val event: AnalyticsEvent) : WebViewResult()
}
