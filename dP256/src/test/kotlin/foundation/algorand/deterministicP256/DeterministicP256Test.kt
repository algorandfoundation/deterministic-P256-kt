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

import cash.z.ecc.android.bip39.Mnemonics.ChecksumException
import cash.z.ecc.android.bip39.Mnemonics.InvalidWordException
import java.math.BigInteger
import java.security.Signature
import java.security.interfaces.ECPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.bouncycastle.crypto.signers.StandardDSAEncoding
import org.bouncycastle.jce.ECNamedCurveTable
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance

class DeterministicP256Test {

        @TestInstance(TestInstance.Lifecycle.PER_CLASS)
        internal class keypairGenerationTest {
                private lateinit var D: DeterministicP256

                @BeforeAll
                fun setUp() {
                        D = DeterministicP256()
                }

                @Test
                fun validSeedPhraseTest() {
                        val DerivedMainKey =
                                D.genDerivedMainKeyWithBIP39(
                                        "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
                                )

                        assertEquals(
                                DerivedMainKey.contentToString(),
                                "[26, -46, -70, -105, 53, 65, -1, 61, 98, 59, 90, -126, -108, 59, 107, 10, -62, 93, -80, 122, 14, -86, 38, -17, -32, -42, -28, 123, -35, 66, 119, -42, 69, 38, 18, 110, 77, -24, -30, -30, -39, -103, 123, 0, -37, 119, 52, -38, 43, 42, 24, -31, 70, -68, 11, 77, -56, -57, -45, -115, 75, -92, 35, -30]"
                        )

                        // Test default parameters
                        val DerivedMainKeyFixedParams =
                                D.genDerivedMainKeyWithBIP39(
                                        phrase =
                                                "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice",
                                        salt = "liquid".toByteArray(),
                                        iterationCount = 210_000,
                                        keyLength = 512
                                )

                        assertEquals(
                                DerivedMainKey.contentToString(),
                                DerivedMainKeyFixedParams.contentToString()
                        )

                        // Test with non-default parameters
                        val DerivedMainKeyNonDef =
                                D.genDerivedMainKeyWithBIP39(
                                        "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice",
                                        iterationCount = 600_000
                                )

                        assertEquals(
                                DerivedMainKeyNonDef.contentToString(),
                                "[-87, 35, 83, 123, -109, 61, 98, 116, -35, 56, -80, -101, 108, -51, 5, -62, 85, 56, -100, 40, -74, 57, 121, 85, -30, -16, 37, -32, 34, -102, -113, 28, 111, -3, -96, 88, -36, 119, -1, 18, 63, -85, 78, 83, -73, -68, -79, -69, 64, -120, -69, 58, -26, 94, -83, 119, -66, -88, -76, -8, -83, -67, 58, -6]"
                        )
                }

                @Test
                fun invalidSeedPhrasesTest() {
                        assertFailsWith<ChecksumException> {
                                D.genDerivedMainKeyWithBIP39(
                                        "zoo zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
                                )
                        }
                        assertFailsWith<InvalidWordException> {
                                D.genDerivedMainKeyWithBIP39(
                                        "algorand zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
                                )
                        }
                }

                @Test
                fun keyPairGenerationTest() {
                        val DerivedMainKey =
                                D.genDerivedMainKeyWithBIP39(
                                        "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
                                )

                        // Example values taken from: https://webauthn.guide/#registration
                        val origin = "https://webauthn.guide"
                        val userId = "a2bd8bf7-2145-4a5a-910f-8fdc9ef421d3"

                        val keyPair = D.genDomainSpecificKeypair(DerivedMainKey, origin, userId)

                        val keyPair0 =
                                D.genDomainSpecificKeypair(
                                        DerivedMainKey,
                                        origin,
                                        userId,
                                        counter = 0
                                )

                        val keyPair1 =
                                D.genDomainSpecificKeypair(
                                        DerivedMainKey,
                                        origin,
                                        userId,
                                        counter = 1
                                )

                        // Check generated public key against hardcoded value
                        assertEquals(
                                keyPair.public.encoded.contentToString(),
                                "[48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0, 4, 55, -123, -88, 32, 86, 59, 61, 35, 82, -35, 57, -71, 59, -12, 100, 95, -23, -122, 87, 60, -43, -59, -68, 118, -74, 82, -85, 97, -70, -60, -28, -73, -34, -86, 59, 65, -37, -108, -91, 120, 41, -95, -87, -1, -36, -68, -72, -78, -112, 95, -122, 97, 105, -112, -82, -104, -21, 19, 98, -49, 114, 59, -127, 76]",
                                "Public key should match hardcoded value!"
                        )

                        // Check that the expected "Pure" Public Key Bytes are produced, without any
                        // metadata. This should be the same across all language implementations
                        assertEquals(
                                D.getPurePKBytes(keyPair).joinToString(", ") {
                                        it.toUByte().toString()
                                        // Force Kotlin's standard signed byte to unsigned
                                },
                                "55, 133, 168, 32, 86, 59, 61, 35, 82, 221, 57, 185, 59, 244, 100, 95, 233, 134, 87, 60, 213, 197, 188, 118, 182, 82, 171, 97, 186, 196, 228, 183, 222, 170, 59, 65, 219, 148, 165, 120, 41, 161, 169, 255, 220, 188, 184, 178, 144, 95, 134, 97, 105, 144, 174, 152, 235, 19, 98, 207, 114, 59, 129, 76",
                                "Public key should match hardcoded value!"
                        )

                        // Check default counter value and that the same key is generated
                        // deterministically twice in a row
                        assertEquals(
                                keyPair.public.encoded.contentToString(),
                                keyPair0.public.encoded.contentToString(),
                                "Keys with the same counter value should be the same!"
                        )

                        // Check that different counter values produce different keys
                        assertNotEquals(
                                keyPair.public.encoded.contentToString(),
                                keyPair1.public.encoded.contentToString(),
                                "Keys with different counter values should be different!"
                        )

                        // Additional check of the same key generation
                        assertEquals(
                                keyPair1.public.encoded.contentToString(),
                                D.genDomainSpecificKeypair(
                                                DerivedMainKey,
                                                origin,
                                                userId,
                                                counter = 1
                                        )
                                        .public
                                        .encoded
                                        .contentToString(),
                                "Keys with the same counter value should be the same!"
                        )

                        val message = "Hello, World!".toByteArray()
                        val signature = D.signWithDomainSpecificKeyPair(keyPair, message)

                        /**
                         * For future reference, use the following to decode the signature into (r,
                         * s) as BigIntegers which can in turn be turned into ByteArrays (e.g. to
                         * check interoperability):
                         *
                         * import org.bouncycastle.crypto.signers.StandardDSAEncoding
                         *
                         * import org.bouncycastle.jce.ECNamedCurveTable
                         *
                         * val rawSignature =
                         * StandardDSAEncoding.INSTANCE.decode(ECNamedCurveTable.getParameterSpec("secp256r1").n,signature)
                         */

                        // Check that the signature is valid
                        val sig = Signature.getInstance("SHA256withECDSA")

                        sig.initVerify(keyPair.public as ECPublicKey)
                        sig.update(message)
                        assertTrue(sig.verify(signature), "Signature should be valid!")

                        // Note that ECDSA signatures are non-deterministic (see ECDSA nonce-reuse
                        // attack) so we cannot hardcoe and compared outputs across rounds of tests
                        // the same way we could with Ed25519.

                        // Check that a false signature is invalid
                        val sigFalse = Signature.getInstance("SHA256withECDSA")
                        sigFalse.initVerify(keyPair.public as ECPublicKey)
                        sigFalse.update(message + byteArrayOf(0))
                        assertTrue(!sigFalse.verify(signature), "Signature should be invalid!")

                        // Check that the signature produced from the Swift version with the same
                        // keypair can be verified with java.security and is valid

                        /**
                         * The following is a Distinguished Encoding Rules (DER) representation of a
                         * P256 signature, produced with Apple's CryptoKit P256 in the Swift
                         * implementation
                         * https://developer.apple.com/documentation/cryptokit/p256/signing/ecdsasignature/derrepresentation
                         */
                        val signatureSwiftDER =
                                listOf(
                                                48,
                                                69,
                                                2,
                                                32,
                                                127,
                                                107,
                                                109,
                                                225,
                                                190,
                                                214,
                                                81,
                                                65,
                                                58,
                                                180,
                                                206,
                                                218,
                                                92,
                                                175,
                                                171,
                                                252,
                                                192,
                                                157,
                                                115,
                                                144,
                                                38,
                                                137,
                                                129,
                                                204,
                                                209,
                                                101,
                                                83,
                                                36,
                                                51,
                                                234,
                                                99,
                                                159,
                                                2,
                                                33,
                                                0,
                                                187,
                                                26,
                                                253,
                                                183,
                                                121,
                                                69,
                                                71,
                                                251,
                                                2,
                                                86,
                                                59,
                                                114,
                                                37,
                                                194,
                                                137,
                                                222,
                                                246,
                                                245,
                                                204,
                                                13,
                                                60,
                                                172,
                                                232,
                                                54,
                                                189,
                                                179,
                                                126,
                                                142,
                                                42,
                                                7,
                                                115,
                                                166
                                        )
                                        .map { it.toByte() }
                                        .toByteArray()

                        val sigSwiftDER = Signature.getInstance("SHA256withECDSA")
                        sigSwiftDER.initVerify(keyPair.public as ECPublicKey)
                        sigSwiftDER.update(message)
                        assertTrue(
                                sigSwiftDER.verify(signatureSwiftDER),
                                "Swift Signature should be valid!"
                        )

                        val signatureSwiftRaw =
                                listOf(
                                                119,
                                                124,
                                                251,
                                                123,
                                                152,
                                                78,
                                                241,
                                                140,
                                                206,
                                                99,
                                                191,
                                                249,
                                                154,
                                                42,
                                                171,
                                                250,
                                                252,
                                                249,
                                                124,
                                                245,
                                                143,
                                                49,
                                                151,
                                                196,
                                                145,
                                                222,
                                                88,
                                                52,
                                                93,
                                                104,
                                                189,
                                                53,
                                                233,
                                                202,
                                                254,
                                                29,
                                                49,
                                                95,
                                                47,
                                                218,
                                                79,
                                                247,
                                                78,
                                                7,
                                                187,
                                                137,
                                                108,
                                                224,
                                                131,
                                                44,
                                                52,
                                                149,
                                                18,
                                                85,
                                                46,
                                                125,
                                                179,
                                                232,
                                                140,
                                                67,
                                                174,
                                                133,
                                                216,
                                                133
                                        )
                                        .map { it.toByte() }
                                        .toByteArray()

                        /**
                         * The following is a signature by Swift library (Apple CryptoKit P256
                         * P256.Signing P256.Signing.PrivateKey) in the raw representation format,
                         * containing only the 32 bytes of r and s.
                         *
                         * We encode it into DER format before verifying it with java.security
                         *
                         * https://github.com/bcgit/bc-java/blob/581c10c7774289433d214bb6ae1ad9ca0618d4f0/core/src/main/java/org/bouncycastle/crypto/signers/StandardDSAEncoding.java#L19
                         * https://github.com/bcgit/bc-java/blob/581c10c7774289433d214bb6ae1ad9ca0618d4f0/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/dsa/DSASigner.java#L104
                         * https://github.com/bcgit/bc-java/blob/581c10c7774289433d214bb6ae1ad9ca0618d4f0/core/src/main/java/org/bouncycastle/crypto/signers/ECDSASigner.java#L95
                         *
                         * It is included here as an extra check of interoperability and for future
                         * reference.
                         */
                        val encodedSignatureSwiftRaw =
                                StandardDSAEncoding.INSTANCE.encode(
                                        ECNamedCurveTable.getParameterSpec("secp256r1").n,
                                        BigInteger(1, signatureSwiftRaw.copyOfRange(0, 32)),
                                        BigInteger(1, signatureSwiftRaw.copyOfRange(32, 64))
                                )

                        val sigSwiftRaw = Signature.getInstance("SHA256withECDSA")
                        sigSwiftRaw.initVerify(keyPair.public as ECPublicKey)
                        sigSwiftRaw.update(message)
                        assertTrue(
                                sigSwiftRaw.verify(encodedSignatureSwiftRaw),
                                "Swift Signature should be valid!"
                        )
                }
        }

        @TestInstance(TestInstance.Lifecycle.PER_CLASS)
        internal class fixedSecureRandomTest {

                @Test
                fun testNextBytes() {
                        val fixedValue = byteArrayOf(1, 2, 3, 4, 5)
                        val secureRandom = FixedSecureRandom(fixedValue)

                        val bytes1 = ByteArray(3)
                        secureRandom.nextBytes(bytes1)
                        assertEquals(
                                fixedValue.sliceArray(0..2).contentToString(),
                                bytes1.contentToString()
                        )

                        val bytes2 = ByteArray(2)
                        secureRandom.nextBytes(bytes2)
                        assertEquals(
                                fixedValue.sliceArray(3..4).contentToString(),
                                bytes2.contentToString()
                        )

                        val bytes3 = byteArrayOf(9, 9, 9, 9, 9)
                        secureRandom.nextBytes(
                                bytes3
                        ) // fixedValue has been exhausted so bytes3 should be unchanged
                        assertEquals(
                                byteArrayOf(9, 9, 9, 9, 9).contentToString(),
                                bytes3.contentToString()
                        )
                }

                @Test
                fun testGenerateSeed() {
                        val fixedValue = byteArrayOf(1, 2, 3, 4, 5)
                        val secureRandom = FixedSecureRandom(fixedValue)

                        val seed = secureRandom.generateSeed(4)
                        assertEquals(
                                byteArrayOf(1, 2, 3, 4).contentToString(),
                                seed.contentToString()
                        )

                        val seed2 = secureRandom.generateSeed(4)
                        assertEquals(
                                byteArrayOf(5, 0, 0, 0).contentToString(),
                                seed2.contentToString()
                        ) // 0 because fixedValue is exhausted
                }
        }
}
