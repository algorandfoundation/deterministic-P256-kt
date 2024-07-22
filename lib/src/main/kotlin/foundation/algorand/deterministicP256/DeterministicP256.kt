/**
 *
 * Copyright 2024 Algorand Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package foundation.algorand.deterministicP256

import android.security.keystore.KeyProperties
import cash.z.ecc.android.bip39.Mnemonics.MnemonicCode
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.KeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * DeterministicP256 - a class that generates deterministic P-256 keypairs from a BIP39 phrase and a
 * domain-specific origin and userId.
 *
 * For generating passkeys intended for FIDO2-based authentication to web services, in a
 * deterministic manner that allows a user to regenerate the same keypair on different devices.
 *
 * 1) Start by generating a root seed from a BIP39 phrase using PBKDF2-HMAC-SHA512 with 600k
 * iterations. This should only be run once per device, and the root seed should be stored securely.
 * The mnemonic phrase should only be inputed once and then be discarded by the device.
 *
 * 2) Generate a domain-specific keypair from the root seed, origin, and userId. The origin is the
 * domain of the service, and the userId is the user's unique identifier on that service. A counter
 * can also be set in case it is pertinent to generate multiple passkeys for a service.
 *
 * 3) Sign a payload with the domain-specific keypair. The keypairs can be stored and retreived from
 * storage using some secure storage mechanism.
 */
class DeterministicP256 {
        /** genRootSeedWithBIP39 - wrapper around genRootSeed that validates the BIP39 phrase. */
        fun genRootSeedWithBIP39(
                        phrase: String,
                        salt: ByteArray = "liquid".toByteArray(),
                        iterationCount: Int = 600_000,
                        keyLength: Int = 512
        ): ByteArray {
                MnemonicCode(phrase).validate()
                return genRootSeed(phrase.toCharArray(), salt, iterationCount, keyLength)
        }

        /** genRootSeed - generates a root seed from a char array using PBKDF2-HMAC-SHA512. */
        private fun genRootSeed(
                        entropy: CharArray,
                        salt: ByteArray,
                        iterationCount: Int,
                        keyLength: Int
        ): ByteArray {
                val keySpec: KeySpec = PBEKeySpec(entropy, salt, iterationCount, keyLength)
                val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
                return keyFactory.generateSecret(keySpec).encoded
        }

        /**
         * genDomainSpecificKeypair - generates a domain-specific keypair from a root seed, origin,
         * userid and counter
         */
        fun genDomainSpecificKeypair(
                        rootSeed: ByteArray,
                        origin: String,
                        userId: String,
                        counter: Int = 0
        ): KeyPair {
                val digest = MessageDigest.getInstance("SHA-512")
                val concat =
                                rootSeed +
                                                origin.toByteArray() +
                                                userId.toByteArray() +
                                                ByteBuffer.allocate(4).putInt(counter).array()
                val seed = digest.digest(concat)

                val generator: KeyPairGenerator =
                                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC)

                generator.initialize(ECGenParameterSpec("secp256r1"), FixedSecureRandom(seed))
                return generator.generateKeyPair()
        }

        /** signWithDomainSpecificKeyPair - signs a payload with a domain-specific keypair */
        fun signWithDomainSpecificKeyPair(keyPair: KeyPair, payload: ByteArray): ByteArray {
                val sig = Signature.getInstance("SHA256withECDSA")
                sig.initSign(keyPair.private as ECPrivateKey)
                sig.update(payload)
                return sig.sign()
        }
}

/**
 * FixedSecureRandom - a SecureRandom overwrite that returns a fixed value
 *
 * Inspired by the Algorand Java SDK:
 * https://github.com/algorand/java-algorand-sdk/blob/672b9c38eea77291bebfb9b5d8e49aa97ceaa2e6/src/main/java/com/algorand/algosdk/account/Account.java#L629
 *
 * We require this as input to the KeyPairGenerator, which requires a SecureRandom implementation.
 *
 * This allows us to deterministically generate keypairs from e.g. a BIP39 phrase. Normally it is
 * NOT recommended to generate keypairs from a "broken" SecureRandom implementation as we do, but in
 * our case: 1) we need it to be deterministic, across platforms 2) we are assuming that the
 * underlying BIP39 phrase was generated securely randomly for the rootSeed 3) we are relying on a
 * PBKDF2-HMAC-SHA512 to further harden that rootSeed even more and create separation, 4) each
 * keyPair's seed is a hashed concatenatino of the rootSeed, origin, userId, and counter.
 *
 * The assumption is that the combination of 2 & 3 & 4 creates enough random entropy to make it safe
 * to generate P-256 keypairs in this way.
 */
class FixedSecureRandom(private val fixedValue: ByteArray) : SecureRandom() {
        private var index = 0

        override fun nextBytes(bytes: ByteArray) {
                if (index >= fixedValue.size) {
                        // no more data to copy
                        return
                }
                var len = bytes.size
                if (len > fixedValue.size - index) {
                        len = fixedValue.size - index
                }
                System.arraycopy(fixedValue, index, bytes, 0, len)
                index += len
        }

        override fun generateSeed(numBytes: Int): ByteArray {
                val bytes = ByteArray(numBytes)
                nextBytes(bytes)
                return bytes
        }
}
