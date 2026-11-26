package dev.l2tunnel.android

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.zip.ZipInputStream

/** Summary of a stored Android profile for UI lists (contains zero secret bytes). */
data class StoredProfileSummary(
    val id: String,
    val directory: File,
    val profile: AndroidVpnProfile?,
    /** Best-effort parsed manifest (`client.json` + `android_vpn.json`) even when keys/common.json are still missing. */
    val draftProfile: AndroidVpnProfile?,
    val validationError: String?,
    val keystoreSealed: Boolean,
    val peerKeyFingerprint: String?,
    val clientNoisePubHex: String? = null,
    val clientMemberPubHex: String? = null,
    val presentSecrets: List<String>,
    val presentFiles: Set<String>,
) {
    val isValid: Boolean get() = profile != null && validationError == null
    val editableProfile: AndroidVpnProfile? get() = profile ?: draftProfile
}

/**
 * Multi-profile store under `noBackupFilesDir/profiles/<id>/` with Keystore AES-GCM secret
 * protection (CL-31) and transparent support for legacy `filesDir/profiles/default`.
 */
class ProfileStore(
    private val profilesRoot: File,
    private val legacyDefaultDir: File? = null,
    val secretStore: KeystoreSecretStore = KeystoreSecretStore(),
) {
    private val activeFile: File get() = File(profilesRoot, ".active_profile")

    init {
        profilesRoot.mkdirs()
        KeystoreSecretStore.setOwnerOnlyDir(profilesRoot)
    }

    fun listProfiles(): List<StoredProfileSummary> {
        // Transparently surface legacy `filesDir/profiles/default` if populated via adb/run-as.
        if (legacyDefaultDir != null && File(legacyDefaultDir, "client.json").isFile) {
            val migratedTarget = File(profilesRoot, "default")
            if (!migratedTarget.exists()) {
                copyDirectory(legacyDefaultDir, migratedTarget)
            }
        }
        val dirs = profilesRoot.listFiles()
            ?.filter { it.isDirectory && !it.name.startsWith(".") }
            ?.sortedBy { it.name }
            ?: emptyList()
        return dirs.map { summarize(it) }
    }

    fun activeProfileId(): String? {
        val saved = if (activeFile.isFile) activeFile.readText().trim().ifEmpty { null } else null
        val all = listProfiles()
        if (saved != null && all.any { it.id == saved }) return saved
        return all.firstOrNull { it.isValid }?.id ?: all.firstOrNull()?.id
    }

    fun setActiveProfile(id: String) {
        val dir = profileDir(id)
        require(dir.isDirectory) { "Profile '$id' does not exist" }
        KeystoreSecretStore.writeOwnerOnlyBytes(activeFile, id.toByteArray(Charsets.UTF_8))
    }

    fun profileDir(id: String): File {
        val safe = sanitizeProfileId(id)
        return File(profilesRoot, safe)
    }

    fun summarize(dir: File): StoredProfileSummary {
        val id = dir.name
        val (profile, err) = try {
            AndroidVpnProfile.loadFromDirectory(dir) to null
        } catch (e: Exception) {
            null to (e.message ?: e.javaClass.simpleName)
        }
        val draft = profile ?: try {
            val clientFile = File(dir, "client.json")
            if (clientFile.isFile) {
                val vpnFile = File(dir, "android_vpn.json")
                AndroidVpnProfile.parse(
                    dir,
                    clientFile.readText(),
                    if (vpnFile.isFile) vpnFile.readText() else null,
                )
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
        val peerKeyFile = File(dir, "noise-peer.pub")
        val fingerprint = if (peerKeyFile.isFile) {
            KeystoreSecretStore.sha256ShortHex(peerKeyFile.readBytes())
        } else {
            null
        }
        val clientNoisePubHex = readPublicHex(File(dir, "noise-client.pub"))
        val clientMemberPubHex = readPublicHex(File(dir, "member.pub"))
        val secrets = KeystoreSecretStore.ALL_SECRET_NAMES.filter { secret ->
            File(dir, "$secret${KeystoreSecretStore.ENC_SUFFIX}").isFile || File(dir, secret).isFile
        }
        val present = buildSet {
            for (name in listOf("client.json", "android_vpn.json", "common.json", "noise-peer.pub", "noise-client.pub", "member.pub")) {
                if (File(dir, name).isFile) add(name)
            }
            for (secret in secrets) add(secret)
        }
        return StoredProfileSummary(
            id = id,
            directory = dir,
            profile = profile,
            draftProfile = draft,
            validationError = err,
            keystoreSealed = secretStore.isKeystoreSealed(dir),
            peerKeyFingerprint = fingerprint,
            clientNoisePubHex = clientNoisePubHex,
            clientMemberPubHex = clientMemberPubHex,
            presentSecrets = secrets,
            presentFiles = present,
        )
    }

    fun createNewProfile(
        id: String,
        nativeBinary: File? = null,
        defaultCommonPlanBytes: ByteArray? = null,
    ): StoredProfileSummary {
        val safeId = sanitizeProfileId(id)
        val dir = profileDir(safeId)
        require(!dir.exists()) { "Profile '$safeId' already exists" }
        val template = AndroidVpnProfile(
            profileDir = dir,
            cover = "quic-like",
            udpBind = "0.0.0.0:0",
            udpPeer = "192.168.1.1:24461",
            pathMtu = 1500,
            tunMtu = 1500,
            noiseProfile = "ik",
            handshakeSeconds = 30,
            tuneRepair = "off,1/8,1/4",
            tunAddress = AndroidVpnProfile.DEFAULT_TUN_ADDRESS,
            tunPrefixLength = AndroidVpnProfile.DEFAULT_TUN_PREFIX,
            routes = listOf("0.0.0.0" to 0),
            dnsServers = emptyList(),
        )
        saveEditedProfile(safeId, template)
        if (defaultCommonPlanBytes != null && defaultCommonPlanBytes.isNotEmpty()) {
            KeystoreSecretStore.writeOwnerOnlyBytes(File(dir, "common.json"), defaultCommonPlanBytes)
        }
        if (nativeBinary != null && nativeBinary.isFile && nativeBinary.canExecute()) {
            generateKeysIntoKeystore(safeId, nativeBinary, defaultCommonPlanBytes)
        }
        setActiveProfile(safeId)
        return summarize(dir)
    }

    /**
     * Generates fresh Ed25519 member + X25519 Noise + 32-byte admission keys via the shared Rust
     * binary (`--keygen`), immediately seals all private keys under AndroidKeyStore AES-256-GCM,
     * preserves public keys (`member.pub`, `noise-client.pub`) for server provisioning, and scrubs
     * the temporary keygen staging directory.
     */
    fun generateKeysIntoKeystore(
        id: String,
        nativeBinary: File,
        defaultCommonPlanBytes: ByteArray? = null,
    ): StoredProfileSummary {
        val dir = profileDir(id)
        dir.mkdirs()
        KeystoreSecretStore.setOwnerOnlyDir(dir)
        val tmpDir = File(profilesRoot, ".keygen-${dir.name}-${System.nanoTime()}")
        try {
            tmpDir.mkdirs()
            KeystoreSecretStore.setOwnerOnlyDir(tmpDir)
            val proc = ProcessBuilder(nativeBinary.absolutePath, "--keygen", tmpDir.absolutePath)
                .redirectErrorStream(true)
                .start()
            val out = proc.inputStream.bufferedReader().readText()
            val code = proc.waitFor()
            if (code != 0) {
                throw IOException("Native key generation failed (exit $code): ${out.trim()}")
            }
            for (secret in AndroidVpnProfile.REQUIRED_SECRET_FILES) {
                val raw = File(tmpDir, secret).readBytes()
                try {
                    secretStore.writeEncryptedSecret(dir, secret, raw)
                } finally {
                    raw.fill(0)
                }
            }
            for (pub in listOf("member.pub", "noise-client.pub")) {
                val src = File(tmpDir, pub)
                if (src.isFile) {
                    KeystoreSecretStore.writeOwnerOnlyBytes(File(dir, pub), src.readBytes())
                }
            }
            if (defaultCommonPlanBytes != null && !File(dir, "common.json").isFile) {
                KeystoreSecretStore.writeOwnerOnlyBytes(File(dir, "common.json"), defaultCommonPlanBytes)
            }
            return summarize(dir)
        } finally {
            KeystoreSecretStore.scrubDirectory(tmpDir)
        }
    }

    /** Saves a 32-byte key supplied as 64 hex characters (sealing secrets into AndroidKeyStore). */
    fun saveHexKey32(id: String, fileName: String, hexText: String): StoredProfileSummary {
        val bytes = parseHex32(hexText)
        return try {
            saveCredentialFile(id, fileName, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * Builds a canonical `l2tunnel://v1/connect?...` share URI for profile `id`.
     * Omits all private keys unless `includeSecrets = true`.
     */
    fun exportShareUri(id: String, includeSecrets: Boolean = false): String {
        val dir = profileDir(id)
        val summary = summarize(dir)
        val prof = summary.editableProfile
            ?: throw IOException("Profile '$id' has no valid client.json to share")
        val peerPubFile = File(dir, "noise-peer.pub")
        val peerPub = if (peerPubFile.isFile) {
            val bytes = peerPubFile.readBytes()
            if (bytes.size == 32) bytes else null
        } else {
            null
        }
        val secrets = if (includeSecrets) {
            ShareSecrets(
                admission = readOptionalSecret(dir, "admission.key"),
                noisePrivate = readOptionalSecret(dir, "noise-private.key"),
                memberPk8 = readOptionalSecret(dir, "member.pk8"),
                noisePsk = if (prof.noiseProfile == "ikpsk2") readOptionalSecret(dir, "noise-psk.key") else null,
            )
        } else {
            ShareSecrets()
        }
        try {
            return ShareProfileUri(
                name = id,
                peer = prof.udpPeer,
                cover = prof.cover,
                noise = prof.noiseProfile,
                peerPub = peerPub,
                tunMtu = prof.tunMtu,
                pathMtu = prof.pathMtu,
                handshakeSeconds = prof.handshakeSeconds,
                tun = "${prof.tunAddress}/${prof.tunPrefixLength}",
                routes = prof.routes.map { "${it.first}/${it.second}" },
                dns = prof.dnsServers,
                tuneRepair = prof.tuneRepair,
                secrets = secrets,
            ).encode()
        } finally {
            secrets.zeroize()
        }
    }

    /**
     * Imports a canonical `l2tunnel://v1/connect?...` share URI into a Keystore-sealed profile.
     * - Seals any embedded private keys directly into AndroidKeyStore AES-256-GCM.
     * - If private keys were omitted (safe public URI) and `nativeBinary` is provided,
     *   auto-generates fresh Keystore-sealed client keys so the profile is ready to pair.
     * - Writes bundled `defaultCommonPlanBytes` to `common.json` if provided.
     */
    fun importShareUri(
        uriText: String,
        overrideName: String? = null,
        nativeBinary: File? = null,
        defaultCommonPlanBytes: ByteArray? = null,
    ): StoredProfileSummary {
        val parsed = ShareProfileUri.decode(uriText)
        try {
            val safeId = sanitizeProfileId(overrideName?.takeIf { it.isNotBlank() } ?: parsed.name ?: "shared")
            val dir = profileDir(safeId)
            val profile = parsed.toAndroidVpnProfile(dir)
            saveEditedProfile(safeId, profile)
            if (defaultCommonPlanBytes != null && defaultCommonPlanBytes.isNotEmpty() && !File(dir, "common.json").isFile) {
                KeystoreSecretStore.writeOwnerOnlyBytes(File(dir, "common.json"), defaultCommonPlanBytes)
            }
            parsed.peerPub?.let { pub ->
                KeystoreSecretStore.writeOwnerOnlyBytes(File(dir, "noise-peer.pub"), pub)
            }
            // Generate missing local client keys first if needed, then overlay any URI-supplied secrets.
            val missingClientKey = parsed.secrets.noisePrivate == null || parsed.secrets.memberPk8 == null || parsed.secrets.admission == null
            if (missingClientKey && nativeBinary != null && nativeBinary.isFile && nativeBinary.canExecute()) {
                generateKeysIntoKeystore(safeId, nativeBinary, defaultCommonPlanBytes)
            }
            parsed.secrets.admission?.let { secretStore.writeEncryptedSecret(dir, "admission.key", it) }
            parsed.secrets.noisePrivate?.let { secretStore.writeEncryptedSecret(dir, "noise-private.key", it) }
            parsed.secrets.memberPk8?.let { secretStore.writeEncryptedSecret(dir, "member.pk8", it) }
            parsed.secrets.noisePsk?.let { secretStore.writeEncryptedSecret(dir, "noise-psk.key", it) }
            setActiveProfile(safeId)
            return summarize(dir)
        } finally {
            parsed.secrets.zeroize()
        }
    }

    private fun readOptionalSecret(dir: File, name: String): ByteArray? =
        try {
            secretStore.readSecret(dir, name)
        } catch (_: Exception) {
            null
        }

    private fun readPublicHex(file: File): String? {
        if (!file.isFile) return null
        val bytes = file.readBytes()
        if (bytes.size != 32) return null
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun saveEditedProfile(id: String, updated: AndroidVpnProfile): StoredProfileSummary {
        val dir = profileDir(id)
        dir.mkdirs()
        KeystoreSecretStore.setOwnerOnlyDir(dir)
        // Re-validate before writing so invalid configs are never persisted.
        val clientJson = updated.toClientJson()
        val vpnJson = updated.toAndroidVpnJson()
        AndroidVpnProfile.parse(dir, clientJson, vpnJson)
        KeystoreSecretStore.writeOwnerOnlyBytes(File(dir, "client.json"), clientJson.toByteArray(Charsets.UTF_8))
        KeystoreSecretStore.writeOwnerOnlyBytes(File(dir, "android_vpn.json"), vpnJson.toByteArray(Charsets.UTF_8))
        return summarize(dir)
    }

    fun saveCredentialFile(id: String, fileName: String, bytes: ByteArray): StoredProfileSummary {
        require(fileName in ALLOWED_PROFILE_FILES) { "Unsupported profile file: $fileName" }
        require(bytes.isNotEmpty() && bytes.size <= MAX_SINGLE_FILE_BYTES) {
            "File $fileName size (${bytes.size} bytes) is out of bounds"
        }
        val dir = profileDir(id)
        dir.mkdirs()
        KeystoreSecretStore.setOwnerOnlyDir(dir)
        if (fileName in KeystoreSecretStore.ALL_SECRET_NAMES) {
            secretStore.writeEncryptedSecret(dir, fileName, bytes)
        } else {
            KeystoreSecretStore.writeOwnerOnlyBytes(File(dir, fileName), bytes)
        }
        return summarize(dir)
    }

    fun sealProfileWithKeystore(id: String): StoredProfileSummary {
        val dir = profileDir(id)
        require(dir.isDirectory) { "Profile '$id' does not exist" }
        secretStore.sealPlaintextSecrets(dir)
        return summarize(dir)
    }

    fun duplicateProfile(sourceId: String, targetId: String): StoredProfileSummary {
        val src = profileDir(sourceId)
        val dst = profileDir(targetId)
        require(src.isDirectory) { "Source profile '$sourceId' does not exist" }
        require(!dst.exists()) { "Profile '${dst.name}' already exists" }
        dst.mkdirs()
        KeystoreSecretStore.setOwnerOnlyDir(dst)
        for (name in listOf("client.json", "android_vpn.json", "common.json", "noise-peer.pub")) {
            val f = File(src, name)
            if (f.isFile) {
                KeystoreSecretStore.writeOwnerOnlyBytes(File(dst, name), f.readBytes())
            }
        }
        for (secret in KeystoreSecretStore.ALL_SECRET_NAMES) {
            val enc = File(src, "$secret${KeystoreSecretStore.ENC_SUFFIX}")
            val plain = File(src, secret)
            if (enc.isFile || plain.isFile) {
                val raw = secretStore.readSecret(src, secret)
                try {
                    secretStore.writeEncryptedSecret(dst, secret, raw)
                } finally {
                    raw.fill(0)
                }
            }
        }
        return summarize(dst)
    }

    fun deleteProfile(id: String) {
        val dir = profileDir(id)
        KeystoreSecretStore.scrubDirectory(dir)
        if (legacyDefaultDir != null && dir.name == "default" && legacyDefaultDir.exists()) {
            KeystoreSecretStore.scrubDirectory(legacyDefaultDir)
        }
    }

    /**
     * Imports a `.zip` profile bundle safely (rejects path traversal, enforces bounded size,
     * validates L3 TUN manifest & explicitly refuses TAP/VXLAN, and immediately seals all
     * private keys under Android Keystore AES-256-GCM).
     */
    fun importZipBundle(profileId: String, zipStream: InputStream): StoredProfileSummary {
        val safeId = sanitizeProfileId(profileId)
        val extracted = ProfileZipImporter.readValidatedBundle(zipStream)
        val target = profileDir(safeId)
        val staging = File(profilesRoot, ".import-$safeId-${System.nanoTime()}")
        try {
            staging.mkdirs()
            KeystoreSecretStore.setOwnerOnlyDir(staging)
            for ((name, bytes) in extracted) {
                if (name in KeystoreSecretStore.ALL_SECRET_NAMES) {
                    // Associated data binds ciphertext to final `safeId`.
                    val sealed = secretStore.encrypt(
                        bytes,
                        KeystoreSecretStore.associatedDataFor(safeId, name),
                    )
                    KeystoreSecretStore.writeOwnerOnlyBytes(
                        File(staging, "$name${KeystoreSecretStore.ENC_SUFFIX}"),
                        sealed,
                    )
                } else {
                    KeystoreSecretStore.writeOwnerOnlyBytes(File(staging, name), bytes)
                }
            }
            // Validate full manifest + presence of every required secret before swapping in.
            AndroidVpnProfile.loadFromDirectory(staging)
            if (target.exists()) {
                KeystoreSecretStore.scrubDirectory(target)
            }
            if (!staging.renameTo(target)) {
                throw IOException("Failed to finalize imported profile '$safeId'")
            }
            setActiveProfile(safeId)
            return summarize(target)
        } finally {
            extracted.values.forEach { it.fill(0) }
            if (staging.exists()) {
                KeystoreSecretStore.scrubDirectory(staging)
            }
        }
    }

    private fun copyDirectory(src: File, dst: File) {
        dst.mkdirs()
        KeystoreSecretStore.setOwnerOnlyDir(dst)
        src.listFiles()?.forEach { f ->
            if (f.isFile && (f.name in ALLOWED_PROFILE_FILES || f.name.endsWith(KeystoreSecretStore.ENC_SUFFIX))) {
                KeystoreSecretStore.writeOwnerOnlyBytes(File(dst, f.name), f.readBytes())
            }
        }
    }

    companion object {
        const val MAX_SINGLE_FILE_BYTES = 512 * 1024
        val ALLOWED_PROFILE_FILES: Set<String> = setOf(
            "client.json",
            "android_vpn.json",
            "common.json",
            "noise-peer.pub",
            "noise-client.pub",
            "member.pub",
            "noise-private.key",
            "member.pk8",
            "admission.key",
            "noise-psk.key",
        )

        fun parseHex32(raw: String): ByteArray {
            val cleaned = raw.trim().replace(" ", "").replace(":", "").lowercase()
            require(cleaned.length == 64) { "Expected 64 hex characters (32 bytes), got ${cleaned.length}" }
            val out = ByteArray(32)
            for (i in 0 until 32) {
                val hi = Character.digit(cleaned[i * 2], 16)
                val lo = Character.digit(cleaned[i * 2 + 1], 16)
                require(hi >= 0 && lo >= 0) { "Invalid hex character at position ${i * 2}" }
                out[i] = ((hi shl 4) or lo).toByte()
            }
            return out
        }

        fun sanitizeProfileId(raw: String): String {
            val cleaned = raw.trim().lowercase().replace(Regex("[^a-z0-9._-]"), "-")
                .trim('-', '.')
                .take(40)
            require(cleaned.isNotEmpty()) { "Profile name must contain letters or digits" }
            require(!cleaned.contains("..")) { "Invalid profile name" }
            return cleaned
        }
    }
}

/** Strict, bounded ZIP bundle parser for Android profile import. */
object ProfileZipImporter {
    const val MAX_TOTAL_BYTES = 2 * 1024 * 1024
    const val MAX_ENTRIES = 32

    fun readValidatedBundle(input: InputStream): MutableMap<String, ByteArray> {
        val files = LinkedHashMap<String, ByteArray>()
        var totalBytes = 0
        var entriesSeen = 0
        ZipInputStream(input).use { zis ->
            while (true) {
                val entry = zis.nextEntry ?: break
                entriesSeen += 1
                if (entriesSeen > MAX_ENTRIES) {
                    throw IOException("Profile archive exceeds $MAX_ENTRIES entries")
                }
                if (entry.isDirectory) {
                    zis.closeEntry()
                    continue
                }
                val rawName = entry.name.replace('\\', '/')
                if (rawName.startsWith("/") || rawName.split('/').any { it == ".." }) {
                    throw IOException("Rejected unsafe archive path: ${entry.name}")
                }
                val baseName = rawName.substringAfterLast('/')
                if (baseName !in ProfileStore.ALLOWED_PROFILE_FILES) {
                    zis.closeEntry()
                    continue
                }
                val buf = ByteArrayOutputStream()
                val tmp = ByteArray(8192)
                while (true) {
                    val n = zis.read(tmp)
                    if (n <= 0) break
                    totalBytes += n
                    if (totalBytes > MAX_TOTAL_BYTES) {
                        throw IOException("Profile archive exceeds $MAX_TOTAL_BYTES byte limit")
                    }
                    buf.write(tmp, 0, n)
                }
                files[baseName] = buf.toByteArray()
                zis.closeEntry()
            }
        }
        val clientBytes = files["client.json"]
            ?: throw IOException("Profile archive is missing client.json")
        val vpnText = files["android_vpn.json"]?.toString(Charsets.UTF_8)
        // Parse immediately so unsupported TAP/VXLAN bundles fail before touching disk.
        AndroidVpnProfile.parse(File("import"), clientBytes.toString(Charsets.UTF_8), vpnText)
        for (req in listOf("common.json", "noise-peer.pub") + AndroidVpnProfile.REQUIRED_SECRET_FILES) {
            if (!files.containsKey(req)) {
                throw IOException("Profile archive is missing required file: $req")
            }
        }
        return files
    }
}
