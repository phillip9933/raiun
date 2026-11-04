package eu.opencloud.android.next.core.network

import okhttp3.Dispatcher
import okhttp3.OkHttpClient

/** Account-free transport resources. Credentials are attached only to individual requests. */
object HttpClients {
    private val base by lazy { OkHttpClient() }

    /**
     * Reuse ordinary connections and executor threads, with a separate cancellation scope per owner.
     * Certificate and Wi-Fi policies still replace the pool when transport identity requires isolation.
     */
    fun newBuilder(): OkHttpClient.Builder = base.newBuilder().dispatcher(Dispatcher(base.dispatcher.executorService))

    fun newClient(): OkHttpClient = newBuilder().build()
}
