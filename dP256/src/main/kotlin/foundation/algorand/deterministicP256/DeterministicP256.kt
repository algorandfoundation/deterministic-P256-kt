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

import cash.z.ecc.android.bip39.Mnemonics.MnemonicCode
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.KeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve

val ECDSA_POINT_SIZE = 64

/**
 * DeterministicP256 - a class that generates deterministic P-256 keypairs from a BIP39 phrase and a
 * domain-specific origin and userId.
 *
 * For generating passkeys intended for FIDO2-based authentication to web services, in a
 * deterministic manner that allows a user to regenerate the same keypair on different devices.
 *
 * 1) Start by generating a derived main key from a BIP39 phrase using PBKDF2-HMAC-SHA512 with 210k
 * iterations. This should only be run once per device, and the derived main key should be stored
 * securely. The mnemonic phrase should only be inputed once and then be discarded by the device.
 *
 * 2) Generate a domain-specific keypair from the derived main key, origin, and userId. The origin
 * is the domain of the service, and the userId is the user's unique identifier on that service. A
 * counter can also be set in case it is pertinent to generate multiple passkeys for a service.
 *
 * 3) Sign a payload with the domain-specific keypair. The keypairs can be stored and retreived from
 * storage using some secure storage mechanism.
 */
class DeterministicP256 {

        // Add Bouncy Castle as a security provider
        init {
                Security.addProvider(BouncyCastleProvider())
        }

        /**
         * genDerivedMainKeyWithBIP39 - wrapper around genDerivedMainKey that validates the BIP39
         * phrase.
         */
        fun genDerivedMainKeyWithBIP39(
                phrase: String,
                salt: ByteArray = "liquid".toByteArray(),
                iterationCount: Int = 210_000,
                keyLength: Int = 512
        ): ByteArray {
                MnemonicCode(phrase).validate()
                return genDerivedMainKey(phrase.toCharArray(), salt, iterationCount, keyLength)
        }

        /**
         * genDerivedMainKey - generates a derived main key from a char array using
         * PBKDF2-HMAC-SHA512.
         */
        private fun genDerivedMainKey(
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
         * genDomainSpecificKeypair - generates a domain-specific keypair from a derived main key,
         * origin, userid and counter
         */
        fun genDomainSpecificKeypair(
                derivedMainKey: ByteArray,
                origin: String,
                userId: String,
                counter: Int = 0
        ): KeyPair {
                val digest = MessageDigest.getInstance("SHA-512")
                val concat =
                        derivedMainKey +
                                origin.toByteArray() +
                                userId.toByteArray() +
                                ByteBuffer.allocate(4).putInt(counter).array()
                val seed = digest.digest(concat)

                val curve = SecP256R1Curve()
                val parameterSpec: ECNamedCurveParameterSpec =
                        ECNamedCurveTable.getParameterSpec("secp256r1")

                val domainParams =
                        ECDomainParameters(curve, parameterSpec.g, parameterSpec.n, parameterSpec.h)
                val keyGenParams = ECKeyGenerationParameters(domainParams, FixedSecureRandom(seed))
                val keyPairGenerator = ECKeyPairGenerator()
                keyPairGenerator.init(keyGenParams)

                return convertBouncyCastleKeyPairToJavaKeyPair(keyPairGenerator.generateKeyPair())
        }

        /** signWithDomainSpecificKeyPair - signs a payload with a domain-specific keypair */
        fun signWithDomainSpecificKeyPair(keyPair: KeyPair, payload: ByteArray): ByteArray {
                val sig = Signature.getInstance("SHA256withECDSA", "BC")
                val privateKey = keyPair.private as ECPrivateKey
                sig.initSign(privateKey)
                sig.update(payload)
                return sig.sign()
        }

        /**
         * convertBouncyCastleKeyPairToJavaKeyPair - converts BC-style keypair to
         * Java.Security-style keypair
         */
        fun convertBouncyCastleKeyPairToJavaKeyPair(bcKeyPair: AsymmetricCipherKeyPair): KeyPair {
                val ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
                val curveSpec =
                        ECNamedCurveSpec(
                                ecSpec.name,
                                ecSpec.curve,
                                ecSpec.g,
                                ecSpec.n,
                                ecSpec.h,
                                ecSpec.seed
                        )

                // Extract the private key
                val bcPrivateKey = bcKeyPair.private as ECPrivateKeyParameters
                val privateKeySpec = ECPrivateKeySpec(bcPrivateKey.d, curveSpec)
                val keyFactory = KeyFactory.getInstance("EC")
                val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

                // Extract the public key
                val bcPublicKey = bcKeyPair.public as ECPublicKeyParameters
                val q = bcPublicKey.q
                val publicKeySpec =
                        ECPublicKeySpec(
                                java.security.spec.ECPoint(
                                        q.affineXCoord.toBigInteger(),
                                        q.affineYCoord.toBigInteger()
                                ),
                                curveSpec
                        )
                val publicKey = keyFactory.generatePublic(publicKeySpec) as ECPublicKey

                return KeyPair(publicKey, privateKey)
        }

        /**
         * getPurePKBytes - get the bytes that represent the public key without any metadata
         * specific to any Kotlin implementation. Useful for deterministically creating FIDO2
         * Credential IDs across languages.
         */
        @OptIn(kotlin.ExperimentalUnsignedTypes::class)
        fun getPurePKBytes(keyPair: KeyPair): UByteArray {
                val fullLength = keyPair.public.encoded.size
                return keyPair.public
                        .encoded
                        .copyOfRange(fullLength - ECDSA_POINT_SIZE, fullLength)
                        .toUByteArray()
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
 * underlying BIP39 phrase was generated securely randomly for the derivedMainKey 3) we are relying
 * on a PBKDF2-HMAC-SHA512 to further harden that derivedMainKey even more and create separation, 4)
 * each keyPair's seed is a hashed concatenatino of the derivedMainKey, origin, userId, and counter.
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
