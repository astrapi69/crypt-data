/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.stream.Stream;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;

/**
 * Parameterized tests for
 * {@link KeyAgreementFactory#newKeyAgreement(java.security.PrivateKey, java.security.PublicKey, String, String, boolean)}
 * with and without an explicit provider
 */
class KeyAgreementFactoryProviderParameterizedTest
{

	private static KeyPair alice;
	private static KeyPair bob;

	/**
	 * One key agreement configuration
	 *
	 * @param keyAgreementAlgorithm
	 *            the key agreement algorithm
	 * @param provider
	 *            the provider, may be null for the default provider lookup
	 */
	record KeyAgreementCase(String keyAgreementAlgorithm, String provider) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		// use a curve that both SunEC and BC support (the BC default curve prime239v1 is not
		// supported by SunEC)
		alice = KeyPairFactory.newKeyPair("secp256r1", KeyPairGeneratorAlgorithm.EC.getAlgorithm(),
			"BC");
		bob = KeyPairFactory.newKeyPair("secp256r1", KeyPairGeneratorAlgorithm.EC.getAlgorithm(),
			"BC");
	}

	static Stream<KeyAgreementCase> keyAgreementCases()
	{
		return Stream.of(new KeyAgreementCase("ECDH", null), new KeyAgreementCase("ECDH", "SunEC"),
			new KeyAgreementCase("ECDH", "BC"));
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newKeyAgreement(java.security.PrivateKey, java.security.PublicKey, String, String, boolean)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the key agreement fails
	 */
	@ParameterizedTest
	@MethodSource("keyAgreementCases")
	void newKeyAgreementWithProvider(final KeyAgreementCase testCase) throws Exception
	{
		KeyAgreement aliceAgreement = KeyAgreementFactory.newKeyAgreement(alice.getPrivate(),
			bob.getPublic(), testCase.keyAgreementAlgorithm(), testCase.provider(), true);
		KeyAgreement bobAgreement = KeyAgreementFactory.newKeyAgreement(bob.getPrivate(),
			alice.getPublic(), testCase.keyAgreementAlgorithm(), testCase.provider(), true);

		assertEquals(testCase.keyAgreementAlgorithm(), aliceAgreement.getAlgorithm());
		if (testCase.provider() != null)
		{
			assertEquals(testCase.provider(), aliceAgreement.getProvider().getName());
		}
		// both sides derive the same shared secret
		assertArrayEquals(aliceAgreement.generateSecret(), bobAgreement.generateSecret());
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newKeyAgreement(java.security.PrivateKey, java.security.PublicKey, String, String, boolean)}
	 * with an unknown provider
	 */
	@Test
	void newKeyAgreementWithUnknownProvider()
	{
		assertThrows(NoSuchProviderException.class, () -> KeyAgreementFactory
			.newKeyAgreement(alice.getPrivate(), bob.getPublic(), "ECDH", "NoSuchProvider", true));
	}
}
