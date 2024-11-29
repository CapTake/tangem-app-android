package com.tangem.features.onramp.redirect.model

import com.tangem.core.decompose.model.Model
import com.tangem.core.decompose.model.ParamsContainer
import com.tangem.core.decompose.navigation.Router
import com.tangem.core.navigation.url.UrlOpener
import com.tangem.core.ui.components.appbar.models.TopAppBarButtonUM
import com.tangem.core.ui.extensions.combinedReference
import com.tangem.core.ui.extensions.resourceReference
import com.tangem.core.ui.extensions.stringReference
import com.tangem.core.ui.extensions.wrappedList
import com.tangem.domain.onramp.GetOnrampRedirectUrlUseCase
import com.tangem.features.onramp.impl.R
import com.tangem.features.onramp.redirect.OnrampRedirectComponent
import com.tangem.features.onramp.redirect.entity.OnrampRedirectTopBarUM
import com.tangem.features.onramp.redirect.entity.OnrampRedirectUM
import com.tangem.utils.coroutines.CoroutineDispatcherProvider
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

internal class OnrampRedirectModel @Inject constructor(
    override val dispatchers: CoroutineDispatcherProvider,
    private val urlOpener: UrlOpener,
    private val getOnrampRedirectUrlUseCase: GetOnrampRedirectUrlUseCase,
    router: Router,
    paramsContainer: ParamsContainer,
) : Model() {

    private val params: OnrampRedirectComponent.Params = paramsContainer.require()
    val state = OnrampRedirectUM(
        topBarConfig = OnrampRedirectTopBarUM(
            title = combinedReference(
                resourceReference(R.string.common_buy),
                stringReference(" ${params.cryptoCurrency.name}"),
            ),
            startButtonUM = TopAppBarButtonUM(
                iconRes = R.drawable.ic_close_24,
                onIconClicked = router::pop,
                enabled = true,
            ),
        ),
        providerImageUrl = params.onrampProviderWithQuote.provider.info.imageLarge,
        title = resourceReference(
            R.string.onramp_redirecting_to_provider_title,
            wrappedList(params.onrampProviderWithQuote.provider.info.name),
        ),
        subtitle = resourceReference(
            R.string.onramp_redirecting_to_provider_subtitle,
            wrappedList(params.onrampProviderWithQuote.provider.info.name),
        ),
    )

    init {
        getRedirectUrl()
    }

    private fun getRedirectUrl() {
        modelScope.launch {
            getOnrampRedirectUrlUseCase.invoke(
                userWalletId = params.userWalletId,
                quote = params.onrampProviderWithQuote,
                cryptoCurrency = params.cryptoCurrency,
            )
                .onLeft { Timber.e(it) }
                .onRight { urlOpener.openUrl(it) }
        }
    }
}
