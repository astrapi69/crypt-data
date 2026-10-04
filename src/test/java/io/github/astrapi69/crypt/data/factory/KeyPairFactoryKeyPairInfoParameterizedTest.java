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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.Security;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;

/**
 * Parameterized tests for {@link KeyPairFactory#newKeyPair(KeyPairInfo)} covering the branches for
 * named curves, providers and plain key sizes
 */
class KeyPairFactoryKeyPairInfoParameterizedTest
{

	/**
	 * One {@link KeyPairInfo}
	 *
	 * @param algorithm
	 *            the key pair algorithm
	 * @param curveName
	 *            the named curve, may be null
	 * @param provider
	 *            the provider, may be null
	 * @param keySize
	 *            the key size, only used without a named curve
	 * @param expectedKeyLength
	 *            the key length of the generated private key
	 */
	record KeyPairInfoCase(String algorithm, String curveName, String provider, int keySize,
		int expectedKeyLength) {
	}

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	static Stream<KeyPairInfoCase> keyPairInfoCases()
	{
		return Stream.of(
			// EC without a named curve is delegated to the BC provider, which ignores the key
			// size and uses its default curve (prime239v1, a 239 bit field)
			new KeyPairInfoCase("EC", null, null, 256, 239),
			new KeyPairInfoCase("RSA", null, null, 1024, 1024),
			// EC with a named curve and an explicit provider
			new KeyPairInfoCase("EC", "secp256r1", "SunEC", 0, 256),
			new KeyPairInfoCase("EC", "secp384r1", "BC", 0, 384));
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(KeyPairInfo)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the key pair cannot be generated
	 */
	@ParameterizedTest
	@MethodSource("keyPairInfoCases")
	void newKeyPairFromKeyPairInfo(final KeyPairInfoCase testCase) throws Exception
	{
		KeyPairInfo keyPairInfo = KeyPairInfo.builder().algorithm(testCase.algorithm())
			.eCNamedCurveParameterSpecName(testCase.curveName()).provider(testCase.provider())
			.keySize(testCase.keySize()).build();

		KeyPair actual = KeyPairFactory.newKeyPair(keyPairInfo);

		assertEquals(testCase.algorithm(), actual.getPrivate().getAlgorithm());
		assertEquals(testCase.algorithm(), actual.getPublic().getAlgorithm());
		assertEquals(testCase.expectedKeyLength(),
			PrivateKeyExtensions.getKeyLength(actual.getPrivate()));
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(KeyPairInfo)} with null
	 */
	@Test
	void newKeyPairFromNullKeyPairInfo()
	{
		assertThrows(NullPointerException.class,
			() -> KeyPairFactory.newKeyPair((KeyPairInfo)null));
	}
}
