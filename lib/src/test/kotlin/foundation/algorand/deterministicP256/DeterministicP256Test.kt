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
                                        "[66, -94, -32, -121, 7, 56, -76, 117, -34, -79, 83, -37, 22, -67, 21, 120, -48, 7, 109, -95, 62, 0, 0, 10, 58, -105, 88, -65, -81, 33, 47, -32, -41, -53, -31, 76, -117, 21, 6, 80, -62, 52, -96, 87, -110, 103, -46, -91, -63, 24, -91, -7, -37, 72, -123, 67, 67, 72, -81, 125, -106, -39, 51, 63]"
                        )

                        // Test default parameters
                        val rootSeedFixedParams =
                                        D.genRootSeedWithBIP39(
                                                        phrase =
                                                                        "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice",
                                                        salt = "liquid".toByteArray(),
                                                        iterationCount = 6000000,
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
                                        "[48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0, 4, 86, 92, -71, 97, 28, 114, -49, -54, -69, -121, -44, -31, 76, 56, -37, -90, -32, 126, -55, 73, -44, -126, -111, -91, -92, 82, 42, -8, 50, -104, 75, 10, -10, 95, -14, 126, -34, 66, -113, 12, 77, -3, 7, -35, -73, 38, 7, -65, -128, 53, 33, 60, -52, 113, -30, -41, 7, -107, -89, 0, -61, 9, -35, -55]",
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
