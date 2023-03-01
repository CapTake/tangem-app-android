package com.tangem.tap.domain.walletconnect2.data

import android.app.Application
import com.tangem.tap.domain.walletconnect2.domain.WalletConnectRepository
import com.tangem.tap.domain.walletconnect2.domain.WcJrpcRequestsDeserializer
import com.tangem.tap.domain.walletconnect2.domain.models.Account
import com.tangem.tap.domain.walletconnect2.domain.models.NetworkNamespace
import com.tangem.tap.domain.walletconnect2.domain.models.WalletConnectError
import com.tangem.tap.domain.walletconnect2.domain.models.WalletConnectEvents
import com.tangem.tap.domain.walletconnect2.domain.models.WalletConnectSession
import com.walletconnect.android.Core
import com.walletconnect.android.CoreClient
import com.walletconnect.android.relay.ConnectionType
import com.walletconnect.web3.wallet.client.Wallet
import com.walletconnect.web3.wallet.client.Web3Wallet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.launch
import timber.log.Timber

class WalletConnectRepositoryImpl(
    val application: Application,
    val wcRequestDeserializer: WcJrpcRequestsDeserializer,
) : WalletConnectRepository {

    private var sessionProposal: Wallet.Model.SessionProposal? = null
    private var userNamespaces: Map<NetworkNamespace, List<Account>>? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _events: MutableStateFlow<WalletConnectEvents?> = MutableStateFlow(null)
    override val events: Flow<WalletConnectEvents> = _events.filterNotNull()

    private val _activeSessions: MutableStateFlow<List<WalletConnectSession>> = MutableStateFlow(emptyList())
    override val activeSessions: Flow<List<WalletConnectSession>> = _activeSessions

    override fun init(userWalletName: String) {
        val projectId = "f0d323cd946c2dadf18fb4b6ff336028" // fixme - use prod version
        // Project ID at https://cloud.walletconnect.com/
        val relayUrl = "relay.walletconnect.com"
        val serverUrl = "wss://$relayUrl?projectId=$projectId"
        val connectionType = ConnectionType.AUTOMATIC

        val appMetaData = Core.Model.AppMetaData(
            name = "Tangem $userWalletName",
            description = "Tangem Wallet $userWalletName",
            url = "tangem.com",
            icons = listOf(
                "https://user-images.githubusercontent.com/24321494/124071202-72a00900-da58-11eb-935a-dcdab21de52b.png",
            ),
            redirect = "kotlin-wallet-wc:/request", // Custom Redirect URI
        )

        CoreClient.initialize(
            relayServerUrl = serverUrl,
            connectionType = connectionType,
            application = application,
            metaData = appMetaData,
        ) { error ->
            Timber.d("Error while initializing client: $error")
            scope.launch {
                _events.emit(
                    WalletConnectEvents.SessionApprovalError(
                        WalletConnectError.ExternalApprovalError(error.throwable.message),
                    ),
                )
            }
        }

        val initParams = Wallet.Params.Init(core = CoreClient)

        Web3Wallet.initialize(initParams) { error ->
            Timber.d("Error while initializing Web3Wallet: $error")
            scope.launch {
                _events.emit(
                    WalletConnectEvents.SessionApprovalError(
                        WalletConnectError.ExternalApprovalError(error.throwable.message),
                    ),
                )
            }
        }

        val walletDelegate = defineWalletDelegate()
        Web3Wallet.setWalletDelegate(walletDelegate)
    }

    private fun defineWalletDelegate(): Web3Wallet.WalletDelegate {
        return object : Web3Wallet.WalletDelegate {
            override fun onSessionProposal(sessionProposal: Wallet.Model.SessionProposal) {
                // Triggered when wallet receives the session proposal sent by a Dapp
                Timber.d("sessionProposal: $sessionProposal")
                this@WalletConnectRepositoryImpl.sessionProposal = sessionProposal

                scope.launch {
                    _events.emit(
                        WalletConnectEvents.SessionProposal(
                            sessionProposal.name,
                            sessionProposal.description,
                            sessionProposal.url,
                            sessionProposal.icons,
                            sessionProposal.requiredNamespaces.values.flatMap { it.chains },
                        ),
                    )
                }
            }

            override fun onSessionRequest(sessionRequest: Wallet.Model.SessionRequest) {
                // Triggered when a Dapp sends SessionRequest to sign a transaction or a message
                Timber.d("sessionRequest: $sessionRequest")
                val request = wcRequestDeserializer.deserialize(
                    method = sessionRequest.request.method,
                    params = sessionRequest.request.params,
                )
                Timber.d("sessionRequestParsed: $request")

                scope.launch {
                    _events.emit(
                        WalletConnectEvents.SessionRequest(
                            request = request,
                            chainId = sessionRequest.chainId,
                            topic = sessionRequest.topic,
                            id = sessionRequest.request.id,
                            metaUrl = sessionRequest.peerMetaData?.url ?: "",
                            metaName = sessionRequest.peerMetaData?.name ?: "",
                        ),
                    )
                }
            }

            override fun onAuthRequest(authRequest: Wallet.Model.AuthRequest) {
                // Triggered when Dapp / Requester makes an authorization request
            }

            override fun onSessionDelete(sessionDelete: Wallet.Model.SessionDelete) {
                // Triggered when the session is deleted by the peer
                if (sessionDelete is Wallet.Model.SessionDelete.Success) {
                    scope.launch {
                        _events.emit(WalletConnectEvents.SessionDeleted(sessionDelete.topic))
                    }
                    updateSessions()
                }
                Timber.d("onSessionDelete: $sessionDelete")
            }

            override fun onSessionSettleResponse(settleSessionResponse: Wallet.Model.SettledSessionResponse) {
                // Triggered when wallet receives the session settlement response from Dapp
                Timber.d("onSessionSettleResponse: $settleSessionResponse")
                if (settleSessionResponse is Wallet.Model.SettledSessionResponse.Result) {
                    scope.launch {
                        _events.emit(
                            WalletConnectEvents.SessionApprovalSuccess(
                                topic = settleSessionResponse.session.topic,
                                accounts = userNamespaces?.flatMap { it.value } ?: emptyList(),
                            ),
                        )
                    }
                    updateSessions()
                }
            }

            override fun onSessionUpdateResponse(sessionUpdateResponse: Wallet.Model.SessionUpdateResponse) {
                // Triggered when wallet receives the session update response from Dapp
                Timber.d("onSessionUpdateResponse: $sessionUpdateResponse")
                updateSessions()
            }

            override fun onConnectionStateChange(state: Wallet.Model.ConnectionState) {
                // Triggered whenever the connection state is changed
                Timber.d("onConnectionStateChange: $state")
                if (state.isAvailable) updateSessions()
            }

            override fun onError(error: Wallet.Model.Error) {
                // Triggered whenever there is an issue inside the SDK
            }
        }
    }

    override fun pair(uri: String) {
        Web3Wallet.pair(Wallet.Params.Pair(uri))
    }

    override fun approve(userNamespaces: Map<NetworkNamespace, List<Account>>) {
        this.userNamespaces = userNamespaces

        val sessionProposal: Wallet.Model.SessionProposal = requireNotNull(this.sessionProposal)

        val missingNetworks = findMissingNetworks(
            namespaces = sessionProposal.requiredNamespaces,
            userNamespaces = userNamespaces,
        )
        if (missingNetworks.isNotEmpty()) {
            Timber.e("Unsupported blockchains: $missingNetworks")
            scope.launch {
                _events.emit(
                    WalletConnectEvents.SessionApprovalError(
                        WalletConnectError.ApprovalErrorMissingNetworks(missingNetworks.toList()),
                    ),
                )
            }
            return
        }

        val userChains = userNamespaces.flatMap { namespace ->
            namespace.value.map { it.chainId to "${it.chainId}:${it.walletAddress}" }
        }.groupBy { pair -> pair.first }
            .mapValues { entry -> entry.value.map { pair -> pair.second }.toSet() }

        val preparedNamespaces = sessionProposal.requiredNamespaces.map { requiredNamespace ->
            val accounts = requiredNamespace.value.chains.mapNotNull { userChains[it] }.flatten()

            requiredNamespace.key to Wallet.Model.Namespace.Session(
                accounts = accounts,
                methods = requiredNamespace.value.methods,
                events = requiredNamespace.value.events,
                extensions = null,
            )
        }.toMap()

        val sessionApproval = Wallet.Params.SessionApprove(sessionProposal.proposerPublicKey, preparedNamespaces)

        Timber.d("Session approval is prepared for sending: $sessionApproval")

        Web3Wallet.approveSession(
            params = sessionApproval,
            onSuccess = {
                Timber.d("Approved successfully: $it")
            },
            onError = {
                Timber.d("Error while approving: $it")
                scope.launch {
                    _events.emit(
                        WalletConnectEvents.SessionApprovalError(
                            WalletConnectError.ExternalApprovalError(it.throwable.message),
                        ),
                    )
                }
            },
        )
    }

    override fun sendRequest(topic: String, id: Long, result: String) {
        Web3Wallet.respondSessionRequest(
            params = Wallet.Params.SessionRequestResponse(
                sessionTopic = topic,
                jsonRpcResponse = Wallet.Model.JsonRpcResponse.JsonRpcResult(
                    id = id,
                    result = result,
                ),
            ),
            onSuccess = {},
            onError = {},
        )
    }

    override fun rejectRequest(topic: String, id: Long) {
        Web3Wallet.respondSessionRequest(
            params = Wallet.Params.SessionRequestResponse(
                sessionTopic = topic,
                jsonRpcResponse = Wallet.Model.JsonRpcResponse.JsonRpcError(
                    id = id,
                    code = 0, // fixme - change if needed
                    message = "", // fixme - change if needed
                ),
            ),
            onSuccess = {},
            onError = {},
        )
    }

    override fun reject() {
        Web3Wallet.rejectSession(
            params = Wallet.Params.SessionReject(
                sessionProposal?.proposerPublicKey ?: "",
                "", // fixme - change if needed
            ),
            onSuccess = {
                Timber.d("Rejected successfully: $it")
            },
            onError = {
                Timber.d("Error while rejecting: $it")
            },
        )
    }

    override fun disconnect(topic: String) {
        Web3Wallet.disconnectSession(
            params = Wallet.Params.SessionDisconnect(topic),
            onSuccess = {
                updateSessions()
                Timber.d("Disconnected successfully: $it")
            },
            onError = {
                Timber.d("Error while disconnecting: $it")
            },
        )
    }

    fun send(
        topic: String,
        id: Long,
        data: String,
    ) {
        Web3Wallet.respondSessionRequest(
            params = Wallet.Params.SessionRequestResponse(
                sessionTopic = topic,
                jsonRpcResponse = Wallet.Model.JsonRpcResponse.JsonRpcResult(
                    id = id,
                    result = data,
                ),
            ),
            onError = {},
            onSuccess = {},
        )
    }

    override fun updateSessions() {
        scope.launch {
            val availableSessions = Web3Wallet.getListOfActiveSessions()
                .map {
                    WalletConnectSession(
                        topic = it.topic,
                        icon = it.metaData?.icons?.firstOrNull(),
                        name = it.metaData?.name,
                        url = it.metaData?.url,
                    )
                }
            Timber.d("Available sessions: $availableSessions")
            _activeSessions.emit(availableSessions)
        }
    }

    private fun findMissingNetworks(
        namespaces: Map<String, Wallet.Model.Namespace.Proposal>,
        userNamespaces: Map<NetworkNamespace, List<Account>>,
    ): Collection<String> {
        val requiredChains = namespaces.values.flatMap { it.chains }
        val userChains = userNamespaces.flatMap { it.value.map { account -> account.chainId } }
        return requiredChains.subtract(userChains.toSet())
    }
}
