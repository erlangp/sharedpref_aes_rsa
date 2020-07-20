package com.herokuapp.erlangparasu.sharedpref_aes_rsa.security

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

/**
 * Original author: Yakiv Mospan (https://github.com/temyco/security-workshop-sample)
 *
 * Modified by: Erlang Parasu 2020.
 */

/**
 * This class wraps [KeyStore] class apis with some additional possibilities.
 */
class KeyStoreWrapper(
    private val context: Context
    //private val defaultKeyStoreName: String? = null,
) {

    companion object {
        val KEY_STORE_PROVIDER_ANDROID = "AndroidKeyStore"
        val KEY_STORE_TYPE = "AndroidKeyStore"
        val ALGORITHM_RSA = "RSA"
        val ALGORITHM_AES = "AES"
    }

    private val keyStore: KeyStore = createAndroidKeyStore()

    //private val defaultKeyStoreFile = File(context.filesDir, defaultKeyStoreName)
    //private val defaultKeyStore = createDefaultKeyStore()

    ///**
    // * @return symmetric key from Android Key Store or null if any key with given alias exists
    // */
    //fun getAndroidKeyStoreSymmetricKey(alias: String): SecretKey? {
    //    return keyStore.getKey(alias, null) as SecretKey?
    //}

    ///**
    // * @return symmetric key from Default Key Store or null if any key with given alias exists
    // */
    //fun getDefaultKeyStoreSymmetricKey(alias: String, keyPassword: String): SecretKey? {
    //    return try {
    //        defaultKeyStore.getKey(alias, keyPassword.toCharArray()) as SecretKey
    //    } catch (e: UnrecoverableKeyException) {
    //        null
    //    }
    //}

    /**
     * @return asymmetric keypair from Android Key Store or null if any key with given alias exists
     */
    fun getAndroidKeyStoreAsymmetricKeyPair(alias: String): KeyPair? {
        val password: CharArray? = null

        val privateKey: PrivateKey? = keyStore.getKey(alias, password) as PrivateKey?
        val publicKey: PublicKey? = keyStore.getCertificate(alias)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    /**
     * Remove key with given alias from Android Key Store
     */
    fun removeAndroidKeyStoreKey(alias: String) {
        return keyStore.deleteEntry(alias)
    }

    //fun createDefaultKeyStoreSymmetricKey(alias: String, password: String) {
    //    val key = generateDefaultSymmetricKey()
    //    val keyEntry = KeyStore.SecretKeyEntry(key)
    //
    //    defaultKeyStore.setEntry(
    //        alias,
    //        keyEntry,
    //        KeyStore.PasswordProtection(password.toCharArray())
    //    )
    //    defaultKeyStore.store(FileOutputStream(defaultKeyStoreFile), password.toCharArray())
    //}

    /**
     * Generates symmetric [KeyProperties.KEY_ALGORITHM_AES] key with default [KeyProperties.BLOCK_MODE_CBC] and
     * [KeyProperties.ENCRYPTION_PADDING_NONE] using default provider.
     */
    fun generateDefaultSymmetricKey(): SecretKey {
        val keyGenerator: KeyGenerator = KeyGenerator.getInstance(ALGORITHM_AES)
        //Log.d("TAG", "generateDefaultSymmetricKey: ${keyGenerator.provider.name}")
        //Log.d("TAG", "generateDefaultSymmetricKey: ${keyGenerator.algorithm}")
        //Log.d("TAG", "generateDefaultSymmetricKey: ${keyGenerator.algorithm.length}")
        return keyGenerator.generateKey()
    }

    ///**
    // * Creates symmetric [KeyProperties.KEY_ALGORITHM_AES] key with default [KeyProperties.BLOCK_MODE_CBC] and
    // * [KeyProperties.ENCRYPTION_PADDING_NONE] and saves it to Android Key Store.
    // */
    //@TargetApi(Build.VERSION_CODES.M)
    //fun createAndroidKeyStoreSymmetricKey(
    //    alias: String,
    //    userAuthenticationRequired: Boolean = false,
    //    invalidatedByBiometricEnrollment: Boolean = true,
    //    userAuthenticationValidityDurationSeconds: Int = -1,
    //    userAuthenticationValidWhileOnBody: Boolean = true
    //): SecretKey {
    //    val keyGenerator =
    //        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    //    val builder =
    //        KeyGenParameterSpec.Builder(
    //            alias,
    //            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    //        )
    //            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
    //            // Require the user to authenticate with a fingerprint to authorize every use of the key
    //            .setUserAuthenticationRequired(userAuthenticationRequired)
    //            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    //            .setUserAuthenticationValidityDurationSeconds(
    //                userAuthenticationValidityDurationSeconds
    //            )
    //            // Not working on api 23, try higher ?
    //            .setRandomizedEncryptionRequired(false)
    //    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
    //        builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
    //        builder.setUserAuthenticationValidWhileOnBody(userAuthenticationValidWhileOnBody)
    //    }
    //    keyGenerator.init(builder.build())
    //    return keyGenerator.generateKey()
    //}

    /**
     * Creates asymmetric RSA key with default [KeyProperties.BLOCK_MODE_ECB] and
     * [KeyProperties.ENCRYPTION_PADDING_NONE] and saves it to Android Key Store.
     */
    @TargetApi(Build.VERSION_CODES.M)
    fun createAndroidKeyStoreAsymmetricKey(alias: String): KeyPair {
        val generator: KeyPairGenerator =
            KeyPairGenerator.getInstance(ALGORITHM_RSA, KEY_STORE_PROVIDER_ANDROID)

        //Log.d("TAG", "createAndroidKeyStoreAsymmetricKey: ${generator.provider.name}")
        //Log.d("TAG", "createAndroidKeyStoreAsymmetricKey: ${generator.algorithm}")

        //if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
        //    initGeneratorWithKeyGenParameterSpec(generator, alias)
        //} else {
        //    initGeneratorWithKeyPairGeneratorSpec(generator, alias)
        //}

        initGeneratorWithKeyPairGeneratorSpec(generator, alias)

        return generator.generateKeyPair()
    }

    private fun initGeneratorWithKeyPairGeneratorSpec(generator: KeyPairGenerator, alias: String) {
        val startDate: Calendar = Calendar.getInstance()

        val amount = 20
        val endDate: Calendar = Calendar.getInstance()
        endDate.add(Calendar.YEAR, amount)

        val name = "CN=${alias} CA Certificate"
        val builder: KeyPairGeneratorSpec.Builder = KeyPairGeneratorSpec.Builder(context)
            .setAlias(alias)
            .setSerialNumber(BigInteger.ONE)
            .setSubject(X500Principal(name))
            .setStartDate(startDate.time)
            .setEndDate(endDate.time)

        generator.initialize(builder.build())
    }

    //@TargetApi(Build.VERSION_CODES.M)
    //private fun initGeneratorWithKeyGenParameterSpec(generator: KeyPairGenerator, alias: String) {
    //    val builder = KeyGenParameterSpec.Builder(
    //        alias,
    //        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    //    )
    //        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
    //        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) // PKCS1Padding
    //        .setRandomizedEncryptionRequired(true)
    //
    //    generator.initialize(builder.build())
    //}

    private fun createAndroidKeyStore(): KeyStore {
        val param: KeyStore.LoadStoreParameter? = null

        val keyStore: KeyStore = KeyStore.getInstance(KEY_STORE_TYPE)
        keyStore.load(param)

        return keyStore
    }

    //private fun createDefaultKeyStore(): KeyStore {
    //    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    //
    //    if (!defaultKeyStoreFile.exists()) {
    //        keyStore.load(null)
    //    } else {
    //        keyStore.load(FileInputStream(defaultKeyStoreFile), null)
    //    }
    //    return keyStore
    //}

}
