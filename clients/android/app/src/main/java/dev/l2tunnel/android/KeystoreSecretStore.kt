package dev.l2tunnel.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Abstraction over master key retrieval so JVM unit tests can exercise exact AES-GCM framing. */
interface SecretKeyProvider {
    fun getOrCreateMasterKey(): SecretKey
}

/**
 * Hardware-backed (where available) non-exportable AES-256-GCM master key in `AndroidKeyStore`
 * (CL-31: envelope encryption for Rust Noise/Ed25519/admission key bytes at rest).
 */
class AndroidKeystoreKeyProvider(
    private val alias: String = DEFAULT_KEY_ALIAS,
) : SecretKeyProvider {
    override fun getOrCreateMasterKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = ks.getKey(alias, null) as? SecretKey
        if (existing != null) return existing
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        gen.init(spec)
        return gen.generateKey()
    }

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val DEFAULT_KEY_ALIAS = "l2tunnel_profile_master_v1"
    }
}

/**
 * AES-256-GCM envelope store for Android profile secrets (CL-31).
 *
 * Wire format on disk (`<name>.enc`, mode `0600` under `noBackupFilesDir`):
 * `[4-byte magic "L2K\x01" | 12-byte GCM IV | ciphertext + 16-byte authentication tag]`.
 *
 * Plaintext secrets are never logged or returned to UI strings; they are only materialized into
 * an ephemeral `0700`/`0600` runtime directory for the Rust service startup and immediately
 * overwritten with zeros and unlinked once the Rust process signals readiness (`R`) or stops.
 */
class KeystoreSecretStore(
    private val keyProvider: SecretKeyProvider = AndroidKeystoreKeyProvider(),
) {
    fun encrypt(plaintext: ByteArray, associatedData: ByteArray = ByteArray(0)): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, keyProvider.getOrCreateMasterKey())
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }
        val iv = cipher.iv
        require(iv != null && iv.size == GCM_IV_BYTES) { "Unexpected GCM IV length" }
        val ciphertext = cipher.doFinal(plaintext)
        val out = ByteArray(MAGIC.size + GCM_IV_BYTES + ciphertext.size)
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.size)
        System.arraycopy(iv, 0, out, MAGIC.size, GCM_IV_BYTES)
        System.arraycopy(ciphertext, 0, out, MAGIC.size + GCM_IV_BYTES, ciphertext.size)
        return out
    }

    fun decrypt(blob: ByteArray, associatedData: ByteArray = ByteArray(0)): ByteArray {
        if (blob.size <= MAGIC.size + GCM_IV_BYTES + GCM_TAG_BYTES) {
            throw IOException("Encrypted secret blob is truncated")
        }
        for (i in MAGIC.indices) {
            if (blob[i] != MAGIC[i]) {
                throw IOException("Encrypted secret blob has invalid header")
            }
        }
        val iv = blob.copyOfRange(MAGIC.size, MAGIC.size + GCM_IV_BYTES)
        val ciphertext = blob.copyOfRange(MAGIC.size + GCM_IV_BYTES, blob.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            keyProvider.getOrCreateMasterKey(),
            GCMParameterSpec(GCM_TAG_BITS, iv),
        )
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }
        return cipher.doFinal(ciphertext)
    }

    /** Writes an encrypted secret `<name>.enc` atomically and removes any legacy plaintext file. */
    fun writeEncryptedSecret(profileDir: File, secretName: String, plaintext: ByteArray) {
        val aad = associatedDataFor(profileDir.name, secretName)
        val sealed = encrypt(plaintext, aad)
        val encFile = File(profileDir, "$secretName$ENC_SUFFIX")
        val tmpFile = File(profileDir, "$secretName$ENC_SUFFIX.tmp")
        writeOwnerOnlyBytes(tmpFile, sealed)
        if (!tmpFile.renameTo(encFile)) {
            writeOwnerOnlyBytes(encFile, sealed)
            tmpFile.delete()
        }
        // Scrub any leftover plaintext copy immediately.
        val plainFile = File(profileDir, secretName)
        if (plainFile.exists()) {
            scrubFile(plainFile)
        }
    }

    /**
     * Reads a profile secret (preferring Keystore-encrypted `<name>.enc`, with fallback to legacy
     * plaintext for developer/harness staging). Callers must zero the returned array after use.
     */
    fun readSecret(profileDir: File, secretName: String): ByteArray {
        val encFile = File(profileDir, "$secretName$ENC_SUFFIX")
        if (encFile.isFile) {
            val aad = associatedDataFor(profileDir.name, secretName)
            return decrypt(encFile.readBytes(), aad)
        }
        val plainFile = File(profileDir, secretName)
        if (plainFile.isFile) {
            return plainFile.readBytes()
        }
        throw IOException("Missing secret file: $secretName")
    }

    /** Migrates any plaintext secret files in `profileDir` into Keystore-encrypted `.enc` blobs. */
    fun sealPlaintextSecrets(profileDir: File): Int {
        var migrated = 0
        for (secret in ALL_SECRET_NAMES) {
            val plain = File(profileDir, secret)
            if (plain.isFile) {
                val bytes = plain.readBytes()
                try {
                    writeEncryptedSecret(profileDir, secret, bytes)
                    migrated += 1
                } finally {
                    bytes.fill(0)
                }
            }
        }
        return migrated
    }

    /**
     * Materializes a complete `0700`/`0600` ephemeral runtime directory for `l2tunnel-android-service`.
     * Caller MUST invoke [scrubDirectory] once the Rust service reports readiness (`R`) or exits.
     */
    fun materializeRuntimeDirectory(profileDir: File, runtimeDir: File): File {
        if (runtimeDir.exists()) {
            scrubDirectory(runtimeDir)
        }
        runtimeDir.mkdirs()
        setOwnerOnlyDir(runtimeDir)

        for (name in listOf("client.json", "common.json", "noise-peer.pub", "android_vpn.json")) {
            val src = File(profileDir, name)
            if (src.isFile) {
                writeOwnerOnlyBytes(File(runtimeDir, name), src.readBytes())
            }
        }
        for (secret in ALL_SECRET_NAMES) {
            val enc = File(profileDir, "$secret$ENC_SUFFIX")
            val plain = File(profileDir, secret)
            if (enc.isFile || plain.isFile) {
                val raw = readSecret(profileDir, secret)
                try {
                    writeOwnerOnlyBytes(File(runtimeDir, secret), raw)
                } finally {
                    raw.fill(0)
                }
            }
        }
        return runtimeDir
    }

    fun isKeystoreSealed(profileDir: File): Boolean =
        AndroidVpnProfile.REQUIRED_SECRET_FILES.all { secret ->
            File(profileDir, "$secret$ENC_SUFFIX").isFile && !File(profileDir, secret).exists()
        }

    companion object {
        const val ENC_SUFFIX = ".enc"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BYTES = 16
        private const val GCM_TAG_BITS = 128
        private val MAGIC = byteArrayOf(0x4C, 0x32, 0x4B, 0x01) // "L2K\x01"
        val ALL_SECRET_NAMES: List<String> =
            AndroidVpnProfile.REQUIRED_SECRET_FILES + AndroidVpnProfile.OPTIONAL_SECRET_FILES

        fun associatedDataFor(profileId: String, secretName: String): ByteArray =
            "l2tunnel-android-v1:$profileId:$secretName".toByteArray(Charsets.UTF_8)

        fun sha256ShortHex(bytes: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            return digest.take(8).joinToString("") { "%02x".format(it) }
        }

        fun setOwnerOnlyDir(dir: File) {
            dir.setReadable(false, false)
            dir.setWritable(false, false)
            dir.setExecutable(false, false)
            dir.setReadable(true, true)
            dir.setWritable(true, true)
            dir.setExecutable(true, true)
        }

        fun writeOwnerOnlyBytes(file: File, bytes: ByteArray) {
            FileOutputStream(file).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setExecutable(false, false)
            file.setReadable(true, true)
            file.setWritable(true, true)
        }

        fun scrubFile(file: File) {
            if (!file.exists()) return
            try {
                if (file.isFile) {
                    val len = file.length().coerceAtMost(4L * 1024L * 1024L).toInt()
                    if (len > 0) {
                        FileOutputStream(file).use { out ->
                            out.write(ByteArray(len))
                            out.fd.sync()
                        }
                    }
                }
            } catch (_: Exception) {
            }
            file.delete()
        }

        fun scrubDirectory(dir: File) {
            if (!dir.exists()) return
            dir.listFiles()?.forEach { child ->
                if (child.isDirectory) {
                    scrubDirectory(child)
                } else {
                    scrubFile(child)
                }
            }
            dir.delete()
        }
    }
}
