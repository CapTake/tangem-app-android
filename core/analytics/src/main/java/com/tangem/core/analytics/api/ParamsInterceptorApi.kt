package com.tangem.core.analytics.api

import com.tangem.core.analytics.models.AnalyticsEvent
import com.tangem.core.analytics.models.EventValue

/**
 * Created by Anton Zhilenkov on 02.11.2022.
 */
interface ParamsInterceptor {
    fun id(): String
    fun canBeAppliedTo(event: AnalyticsEvent): Boolean
    fun intercept(params: MutableMap<String, EventValue>)
}

interface ParamsInterceptorHolder {
    fun addParamsInterceptor(interceptor: ParamsInterceptor)
    fun removeParamsInterceptor(interceptorId: String): ParamsInterceptor?
}
