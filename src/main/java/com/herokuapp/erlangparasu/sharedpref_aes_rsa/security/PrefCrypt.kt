package com.herokuapp.erlangparasu.sharedpref_aes_rsa.security

import android.content.Context
import android.util.Base64
import java.security.KeyPair
import java.util.*
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Created by Erlang Parasu on 2010.
 */

class PrefCrypt(ctx: Context, appId: String) {

    private val _context: Context = ctx.applicationContext
    private val _ksWrapper = KeyStoreWrapper(_context)
    private val _app_id = appId

    private var _keyPair: KeyPair? = null
    private var _secretKey: SecretKey? = null

    private val SP_PREF_DEFAULT = _app_id + "." + "MY_SP_PREF_DEFAULT"

    companion object {
        //private const val KEYSTORE_DEFAULT = "MY_KEYSTORE_DEFAULT"
        private const val ALIAS_DEFAULT = "MY_ALIAS_DEFAULT"

        private const val SP_KEY_DEFAULT_AES = "MY_SP_KEY_DEFAULT_AES"
    }

    fun setup(): PrefCrypt {
        try {
            fetchOldKeys()
        } catch (th: Throwable) {
            resetKeys()
            recreateSecretKey(getOldKeyPair()!!)
        } finally {
            fetchOldKeys()
        }

        return this
    }

    private fun resetKeys() {
        savePref(SP_PREF_DEFAULT, SP_KEY_DEFAULT_AES, "")
        _ksWrapper.removeAndroidKeyStoreKey(ALIAS_DEFAULT)
    }

    fun write(
        prefName: String,
        key: String,
        value: String
    ): Boolean {
        try {
            val plainData: String = value
            val cipherEncryption = CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC)
            val encryptedStr: String =
                cipherEncryption.encrypt(plainData, _secretKey, true)

            return savePref(prefName, key, encryptedStr)
        } catch (th: Throwable) {
            //throw RuntimeException("ERR: Failed to encrypt and save data", th)
        }

        return false
    }

    fun read(
        prefName: String,
        key: String,
        defaultValue: String
    ): String {
        val encryptedData: String = getPref(prefName, key, defaultValue)
        if (encryptedData.isBlank()) {
            return ""
        }

        try {
            val cipherForEncryption = CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC)
            val original: String =
                cipherForEncryption.decrypt(encryptedData, _secretKey, true)

            return original
        } catch (th: Exception) {
            //throw RuntimeException("ERR: " + th.message.toString(), th)
        }

        return ""
    }

    private fun fetchOldKeys() {
        val keyPair: KeyPair = getOldKeyPair()!!
        val secretKey: SecretKey = getOldSecretKey(keyPair)

        val cipherForEncryption = CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC)
        val original: String = "TRY_" + Calendar.getInstance().time.time.toString()

        val encrypted: String = cipherForEncryption.encrypt(original, secretKey, true)
        val decrypted: String = cipherForEncryption.decrypt(encrypted, secretKey, true)

        if (original != decrypted) {
            throw RuntimeException("ERR: Failed to setup encryption")
        }

        _keyPair = keyPair
        _secretKey = secretKey
    }

    private fun getOldKeyPair(): KeyPair? {
        var keyPair: KeyPair? = _ksWrapper.getAndroidKeyStoreAsymmetricKeyPair(ALIAS_DEFAULT)
        if (keyPair == null) {
            keyPair = _ksWrapper.createAndroidKeyStoreAsymmetricKey(ALIAS_DEFAULT)
        }
        return keyPair
    }

    private fun getOldSecretKey(keyPair: KeyPair): SecretKey {
        val encryptedBaseSecretKey: String =
            getPref(SP_PREF_DEFAULT, SP_KEY_DEFAULT_AES, "")

        if (encryptedBaseSecretKey.isBlank()) {
            throw RuntimeException("ERR: default secret key not found")
        }

        try {
            val cipherWrapping = CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
            val baseSecretKey: String =
                cipherWrapping.decrypt(encryptedBaseSecretKey, keyPair.private, false)

            val secretByteArr: ByteArray = Base64.decode(baseSecretKey, Base64.DEFAULT)
            val secretKey: SecretKey = SecretKeySpec(secretByteArr, "AES")

            return secretKey
        } catch (th: Throwable) {
            throw RuntimeException("ERR: " + th.message.toString(), th)
        }
    }

    private fun recreateSecretKey(keyPair: KeyPair): SecretKey {
        val secretKey: SecretKey = _ksWrapper.generateDefaultSymmetricKey()

        val baseSecretKey: String =
            Base64.encodeToString(secretKey.encoded, Base64.DEFAULT)

        val cipherWrapping = CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
        val encryptedBaseSecretKey: String =
            cipherWrapping.encrypt(baseSecretKey, keyPair.public, false)

        savePref(SP_PREF_DEFAULT, SP_KEY_DEFAULT_AES, encryptedBaseSecretKey)

        return secretKey
    }

    private fun savePref(
        prefName: String,
        key: String,
        value: String
    ): Boolean {
        return _context
            .getSharedPreferences(prefName, Context.MODE_PRIVATE)
            .edit()
            .putString(key, value)
            .commit()
    }

    private fun getPref(
        prefName: String,
        key: String,
        defaultValue: String
    ): String {
        return _context
            .getSharedPreferences(prefName, Context.MODE_PRIVATE)
            .getString(key, defaultValue)!!
    }

    private fun sample() {
        //saveOfflineString(context, "MY_WRAPPED_KEY", "")
        //saveOfflineString(context, "my_sample_data", "")

        var keyPair: KeyPair? = _ksWrapper.getAndroidKeyStoreAsymmetricKeyPair(ALIAS_DEFAULT)
        if (keyPair == null) {
            keyPair = _ksWrapper.createAndroidKeyStoreAsymmetricKey(ALIAS_DEFAULT)
        }

        var tempSecretKey: SecretKey? = null

        var prefEncryptedBaseSecretKey: String =
            getPref("PREF", "MY_WRAPPED_KEY", "").toString()
        if (prefEncryptedBaseSecretKey.isBlank()) {
            // WRAP
            try {
                val secretKey: SecretKey = _ksWrapper.generateDefaultSymmetricKey()

                val baseSecretKey: String =
                    Base64.encodeToString(secretKey.encoded, Base64.DEFAULT)
                //Log.d("TAG", "initEncryption: wrap: 1 baseSecretKey: $baseSecretKey")

                val cipherWrapping = CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
                val encryptedBaseSecretKey: String =
                    cipherWrapping.encrypt(baseSecretKey, keyPair.public, false)
                //Log.d(
                //    "TAG",
                //    "initEncryption: wrap: 1 encryptedBaseSecretKey: $encryptedBaseSecretKey"
                //)

                encryptedBaseSecretKey.let {
                    savePref("PREF", "MY_WRAPPED_KEY", it)
                }

                tempSecretKey = secretKey
            } catch (th: Throwable) {
                //if (BuildConfig.DEBUG) {
                //    //Log.e("TAG", "initEncryption: wrap: ${th.message}", th)
                //}

                //Log.d("TAG", "initEncryption: ${th.message.toString()}")
                if (th.message.toString().contains("cipher.iv must not be null")) {
                    return
                }

                return
            }
        }
        //Log.d("TAG", "initEncryption: wrap SUCCESS")

        // UNWRAP
        prefEncryptedBaseSecretKey =
            getPref("PREF", "MY_WRAPPED_KEY", "").toString()
        try {
            //Log.d(
            //    "TAG",
            //    "initEncryption: unwrap: 2 prefEncryptedBaseSecretKey: $prefEncryptedBaseSecretKey"
            //)

            val cipherWrapping = CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
            val baseSecretKey: String =
                cipherWrapping.decrypt(prefEncryptedBaseSecretKey, keyPair.private, false)
            //Log.d("TAG", "initEncryption: unwrap: 2 baseSecretKey: $baseSecretKey")

            val secretByteArr: ByteArray = Base64.decode(baseSecretKey, Base64.DEFAULT)
            val secretKey = SecretKeySpec(secretByteArr, "AES")

            val isTheSame = secretKey == tempSecretKey
            //Log.d("TAG", "initEncryption: unwrap: is equal secret: ${isTheSame}")

            if (!isTheSame) {
                return
            }
        } catch (th: Throwable) {
            if (th.message.toString().contains("bad base-64")) {
                savePref("PREF", "MY_WRAPPED_KEY", "")
            }

            //

            //if (BuildConfig.DEBUG) {
            //    //Log.e("TAG", "initEncryption: unwrap: ${th.message}", th)
            //}

            return
        }
        //Log.d("TAG", "initEncryption: unwrap SUCCESS")

        // TRY READ
        try {
            val encryptedData: String =
                getPref("PREF", "my_sample_data", "").toString()

            if (!encryptedData.isBlank()) {
                val cipherForEncryption = CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC)
                val original: String =
                    cipherForEncryption.decrypt(encryptedData, tempSecretKey, true)
                //Log.d("TAG", "initEncryption: read: original: $original")
            } else {
                //Log.d("TAG", "initEncryption: read is blank")
            }
        } catch (th: Exception) {
            //if (BuildConfig.DEBUG) {
            //    //Log.e("TAG", "initEncryption: read: ${th.message}", th)
            //}
        }


        // TRY READ
        try {
            val encryptedData: String =
                getPref("PREF", "my_sample_data", "").toString()

            if (!encryptedData.isBlank()) {
                val cipherForEncryption = CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC)
                val original: String =
                    cipherForEncryption.decrypt(encryptedData, tempSecretKey, true)
                //Log.d("TAG", "initEncryption: read: original: $original")
            } else {
                //Log.d("TAG", "initEncryption: read is blank")
            }
        } catch (th: Exception) {
            //if (BuildConfig.DEBUG) {
            //    //Log.e("TAG", "initEncryption: read: ${th.message}", th)
            //}
        }

        //
    }
}