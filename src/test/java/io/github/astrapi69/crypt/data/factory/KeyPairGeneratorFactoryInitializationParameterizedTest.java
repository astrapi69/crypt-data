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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.util.stream.Stream;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests that the {@link KeyPairGeneratorFactory} methods really initialize the
 * generator with the requested key size or named curve
 */
class KeyPairGeneratorFactoryInitializationParameterizedTest
{

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * One algorithm with a requested key size in bits
	 *
	 * @param algorithm
	 *            the key pair algorithm
	 * @param keySize
	 *            the requested key size in bits
	 */
	record KeySizeCase(String algorithm, int keySize) {
	}

	/**
	 * One named elliptic curve
	 *
	 * @param curveName
	 *            the name of the curve
	 */
	record CurveCase(String curveName) {
	}

	static Stream<KeySizeCase> keySizeCases()
	{
		return Stream.of(new KeySizeCase("RSA", 1024), new KeySizeCase("RSA", 2048),
			new KeySizeCase("DSA", 1024), new KeySizeCase("DSA", 2048));
	}

	static Stream<CurveCase> curveCases()
	{
		return Stream.of(new CurveCase("secp256k1"), new CurveCase("secp384r1"),
			new CurveCase("brainpoolP256r1"));
	}

	private static int keySizeOf(final KeyPair keyPair)
	{
		if (keyPair.getPublic()instanceof RSAKey rsaKey)
		{
			return rsaKey.getModulus().bitLength();
		}
		if (keyPair.getPublic()instanceof DSAKey dsaKey)
		{
			return dsaKey.getParams().getP().bitLength();
		}
		throw new IllegalArgumentException("unexpected key type " + keyPair.getPublic());
	}

	/**
	 * Test method for
	 * {@link KeyPairGeneratorFactory#newKeyPairGenerator(String, int, SecureRandom)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the generator cannot be created
	 */
	@ParameterizedTest
	@MethodSource("keySizeCases")
	void newKeyPairGeneratorWithSecureRandomUsesRequestedKeySize(final KeySizeCase testCase)
		throws Exception
	{
		KeyPairGenerator generator = KeyPairGeneratorFactory
			.newKeyPairGenerator(testCase.algorithm(), testCase.keySize(), new SecureRandom());

		assertEquals(testCase.algorithm(), generator.getAlgorithm());
		assertEquals(testCase.keySize(), keySizeOf(generator.generateKeyPair()),
			testCase.toString());
	}

	/**
	 * Test method for {@link KeyPairGeneratorFactory#newKeyPairGenerator(String, int)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the generator cannot be created
	 */
	@ParameterizedTest
	@MethodSource("keySizeCases")
	void newKeyPairGeneratorUsesRequestedKeySize(final KeySizeCase testCase) throws Exception
	{
		KeyPairGenerator generator = KeyPairGeneratorFactory
			.newKeyPairGenerator(testCase.algorithm(), testCase.keySize());

		assertEquals(testCase.keySize(), keySizeOf(generator.generateKeyPair()),
			testCase.toString());
	}

	/**
	 * Test method for {@link KeyPairGeneratorFactory#newKeyPairGenerator(String, String, String)}
	 * and
	 * {@link KeyPairGeneratorFactory#newKeyPairGenerator(ECNamedCurveParameterSpec, String, String)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the generator cannot be created
	 */
	@ParameterizedTest
	@MethodSource("curveCases")
	void newKeyPairGeneratorUsesRequestedCurve(final CurveCase testCase) throws Exception
	{
		ECNamedCurveParameterSpec expectedSpec = ECNamedCurveTable
			.getParameterSpec(testCase.curveName());

		KeyPairGenerator byName = KeyPairGeneratorFactory.newKeyPairGenerator(testCase.curveName(),
			"EC", "BC");
		KeyPairGenerator bySpec = KeyPairGeneratorFactory.newKeyPairGenerator(expectedSpec, "EC",
			"BC");

		for (KeyPairGenerator generator : new KeyPairGenerator[] { byName, bySpec })
		{
			ECPublicKey publicKey = (ECPublicKey)generator.generateKeyPair().getPublic();
			assertEquals(expectedSpec.getN(), publicKey.getParams().getOrder(),
				testCase.curveName());
			assertEquals(expectedSpec.getCurve().getFieldSize(),
				publicKey.getParams().getCurve().getField().getFieldSize(), testCase.curveName());
		}
	}
}
