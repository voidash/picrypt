package com.picrypt.widget

import android.content.Context
import android.content.SharedPreferences

/**
 * Centralized SharedPreferences access for Picrypt widget.
 * Avoids scattering preference key strings across multiple files.
 */
object PrefsHelper {

    private const val PREFS_NAME = "picrypt_prefs"
    private const val KEY_SERVER_URL = "server_url"
    private const val KEY_LAST_STATE = "last_state"
    private const val KEY_LOCK_PIN = "lock_pin"

    private fun prefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun getServerUrl(context: Context): String? {
        return prefs(context).getString(KEY_SERVER_URL, null)
    }

    fun setServerUrl(context: Context, url: String) {
        prefs(context).edit().putString(KEY_SERVER_URL, url).apply()
    }

    fun getLastState(context: Context): String {
        return prefs(context).getString(KEY_LAST_STATE, "") ?: ""
    }

    fun setLastState(context: Context, state: String) {
        prefs(context).edit().putString(KEY_LAST_STATE, state).apply()
    }

    fun getLockPin(context: Context): String? {
        return prefs(context).getString(KEY_LOCK_PIN, null)
    }

    fun setLockPin(context: Context, pin: String?) {
        prefs(context).edit().putString(KEY_LOCK_PIN, pin).apply()
    }
}
