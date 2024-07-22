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
                        val rootSeed =
                                        D.genRootSeedWithBIP39(
                                                        "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
                                        )

                        assertEquals(
                                        rootSeed.contentToString(),
                                        "[-87, 35, 83, 123, -109, 61, 98, 116, -35, 56, -80, -101, 108, -51, 5, -62, 85, 56, -100, 40, -74, 57, 121, 85, -30, -16, 37, -32, 34, -102, -113, 28, 111, -3, -96, 88, -36, 119, -1, 18, 63, -85, 78, 83, -73, -68, -79, -69, 64, -120, -69, 58, -26, 94, -83, 119, -66, -88, -76, -8, -83, -67, 58, -6]"
                        )

                        // Test default parameters
                        val rootSeedFixedParams =
                                        D.genRootSeedWithBIP39(
                                                        phrase =
                                                                        "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice",
                                                        salt = "liquid".toByteArray(),
                                                        iterationCount = 600_000,
                                                        keyLength = 512
                                        )

                        assertEquals(
                                        rootSeed.contentToString(),
                                        rootSeedFixedParams.contentToString()
                        )
                }

                @Test
                fun invalidSeedPhrasesTest() {
                        assertFailsWith<ChecksumException> {
                                D.genRootSeedWithBIP39(
                                                "zoo zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
                                )
                        }
                        assertFailsWith<InvalidWordException> {
                                D.genRootSeedWithBIP39(
                                                "algorand zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
                                )
                        }
                }

                @Test
                fun keyPairGenerationTest() {
                        val rootSeed =
                                        D.genRootSeedWithBIP39(
                                                        "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
                                        )

                        // Example values taken from: https://webauthn.guide/#registration
                        val origin = "https://webauthn.guide"
                        val userId = "a2bd8bf7-2145-4a5a-910f-8fdc9ef421d3"

                        val keyPair = D.genDomainSpecificKeypair(rootSeed, origin, userId)
                        val keyPair0 =
                                        D.genDomainSpecificKeypair(
                                                        rootSeed,
                                                        origin,
                                                        userId,
                                                        counter = 0
                                        )
                        val keyPair1 =
                                        D.genDomainSpecificKeypair(
                                                        rootSeed,
                                                        origin,
                                                        userId,
                                                        counter = 1
                                        )

                        // Check generated public key against hardcoded value
                        assertEquals(
                                        keyPair.public.encoded.contentToString(),
                                        "[48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0, 4, -50, -16, 75, 50, -59, 86, 33, 17, -106, 99, 39, -71, -44, 13, 21, -111, 69, -93, 45, 57, 53, 96, -76, -57, 1, -93, 39, 101, -106, -59, -34, 98, -47, -47, -65, 104, 60, 70, -47, 46, 112, 24, -79, 76, -13, 57, 42, -4, -8, -55, 109, -13, -74, -39, 38, 5, 36, 47, -82, 18, -116, -30, -44, 43]",
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
                                                                        rootSeed,
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
}
