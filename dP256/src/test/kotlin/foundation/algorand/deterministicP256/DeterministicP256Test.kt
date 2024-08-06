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
import java.security.Signature
import java.security.interfaces.ECPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
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
                                "[48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0, 4, -51, -127, -4, -41, 35, 55, -122, -27, -104, 70, 74, -26, 65, 1, -45, -8, -22, 121, 109, -30, -70, 23, 113, -51, -9, 52, -77, 76, -102, -14, -80, 64, 89, -121, 14, -65, 0, 119, -104, 55, 22, 96, -13, -80, -23, -123, 41, 61, 91, -11, 47, 87, -49, -36, -10, 16, -112, -17, 96, 78, 102, -25, 71, 45]",
                                "Public key should match hardcoded value!"
                        )

                        // Check default counter value and that the same key is generated
                        // deterministically
                        // twice in a row
                        assertEquals(
                                keyPair.public.toString(),
                                keyPair0.public.toString(),
                                "Keys with the same counter value should be the same!"
                        )

                        // Check that different counter values produce different keys
                        assertNotEquals(
                                keyPair.public.toString(),
                                keyPair1.public.toString(),
                                "Keys with different counter values should be different!"
                        )

                        // Additional check of the same key generation
                        assertEquals(
                                keyPair1.public.toString(),
                                D.genDomainSpecificKeypair(
                                                DerivedMainKey,
                                                origin,
                                                userId,
                                                counter = 1
                                        )
                                        .public
                                        .toString(),
                                "Keys with the same counter value should be the same!"
                        )

                        val message = "Hello, World!".toByteArray()
                        val signature = D.signWithDomainSpecificKeyPair(keyPair, message)

                        // Note that ECDSA signatures are non-deterministic (see ECDSA nonce-reuse
                        // attack)
                        // so they cannot be compared across rounds of tests.

                        // Check that the signature is valid
                        val sig = Signature.getInstance("SHA256withECDSA")
                        sig.initVerify(keyPair.public as ECPublicKey)
                        sig.update(message)
                        assertTrue(sig.verify(signature), "Signature should be valid!")
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
