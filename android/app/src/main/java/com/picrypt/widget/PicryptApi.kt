package com.picrypt.widget

import android.util.Log
import java.io.IOException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import org.json.JSONException
import org.json.JSONObject

/**
 * HTTP helper for communicating with the Picrypt key server.
 * Uses [HttpURLConnection] directly to avoid external dependencies.
 */
class PicryptApi(private val baseUrl: String) {

    companion object {
        private const val TAG = "PicryptApi"
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val READ_TIMEOUT_MS = 10_000
    }

    /**
     * Represents the server state returned by /heartbeat.
     */
    enum class ServerState {
        ACTIVE,
        SEALED,
        LOCKED,
        UNREACHABLE;

        companion object {
            fun fromString(value: String): ServerState {
                return when (value.lowercase()) {
                    "active" -> ACTIVE
                    "sealed" -> SEALED
                    "locked" -> LOCKED
                    else -> {
                        Log.w(TAG, "Unknown server state: $value")
                        UNREACHABLE
                    }
                }
            }
        }
    }

    data class HeartbeatResponse(
        val state: ServerState,
        val timestamp: Long,
    )

    sealed class ApiResult<out T> {
        data class Success<T>(val data: T) : ApiResult<T>()
        data class Failure(val message: String, val exception: Throwable? = null) : ApiResult<Nothing>()
    }

    /**
     * Polls GET /heartbeat to check server status.
     * This is a blocking call -- invoke from a background thread.
     */
    fun heartbeat(): ApiResult<HeartbeatResponse> {
        val url: URL
        try {
            url = URL("$baseUrl/heartbeat")
        } catch (e: Exception) {
            return ApiResult.Failure("Invalid server URL: $baseUrl", e)
        }

        var connection: HttpURLConnection? = null
        return try {
            connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.setRequestProperty("Accept", "application/json")

            val responseCode = connection.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                return ApiResult.Failure("Heartbeat returned HTTP $responseCode")
            }

            val body = connection.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)

            val state = json.optString("state", "")
            if (state.isEmpty()) {
                return ApiResult.Failure("Heartbeat response missing 'state' field")
            }

            val timestamp = json.optLong("timestamp", 0L)

            ApiResult.Success(
                HeartbeatResponse(
                    state = ServerState.fromString(state),
                    timestamp = timestamp,
                )
            )
        } catch (e: SocketTimeoutException) {
            Log.w(TAG, "Heartbeat timed out", e)
            ApiResult.Failure("Connection timed out", e)
        } catch (e: IOException) {
            Log.w(TAG, "Heartbeat I/O error", e)
            ApiResult.Failure("Network error: ${e.message}", e)
        } catch (e: JSONException) {
            Log.e(TAG, "Failed to parse heartbeat response", e)
            ApiResult.Failure("Invalid response format", e)
        } finally {
            connection?.disconnect()
        }
    }

    /**
     * Sends POST /lock to trigger a full lock of all connected devices.
     * This is a blocking call -- invoke from a background thread.
     */
    fun lock(pin: String? = null): ApiResult<Unit> {
        val url: URL
        try {
            url = URL("$baseUrl/lock")
        } catch (e: Exception) {
            return ApiResult.Failure("Invalid server URL: $baseUrl", e)
        }

        var connection: HttpURLConnection? = null
        return try {
            connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.setRequestProperty("Content-Type", "application/json")
            connection.doOutput = true

            // Send lock request body with optional PIN
            val body = if (pin != null) {
                """{"pin":"$pin"}"""
            } else {
                "{}"
            }
            connection.outputStream.use { it.write(body.toByteArray()) }

            val responseCode = connection.responseCode
            if (responseCode in 200..299) {
                ApiResult.Success(Unit)
            } else {
                val errorBody = try {
                    connection.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
                } catch (_: Exception) {
                    ""
                }
                ApiResult.Failure("Lock returned HTTP $responseCode: $errorBody")
            }
        } catch (e: SocketTimeoutException) {
            Log.w(TAG, "Lock request timed out", e)
            ApiResult.Failure("Connection timed out", e)
        } catch (e: IOException) {
            Log.w(TAG, "Lock I/O error", e)
            ApiResult.Failure("Network error: ${e.message}", e)
        } finally {
            connection?.disconnect()
        }
    }
}
