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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Parity tests across the key algorithms a certificate can be made for, and regression tests for
 * issue #33.
 * <p>
 * No single provider covers the set. Bouncy castle knows ec curves the jdk does not implement, and
 * the jdk generates ML-DSA keys bouncy castle refuses to sign with - "unknown private key passed to
 * ML-DSA". Naming either one unconditionally therefore locks out the other half, which is what
 * happened: three signer sites named bouncy castle from the start and could never certify an ML-DSA
 * key, and #28 made the fourth match them.
 */
class CertFactoryAlgorithmParityTest
{

	private static final X500Name NAME = new X500Name("CN=Algorithm Parity");

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static KeyPair newKeyPair(final String algorithm, final int size) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		if (size > 0)
		{
			generator.initialize(size);
		}
		return generator.generateKeyPair();
	}

	/**
	 * Every entry point has to certify every key, whichever provider happens to hold the algorithm.
	 *
	 * @param algorithm
	 *            the key algorithm
	 * @param size
	 *            the key size, or 0 for the default
	 * @param signatureAlgorithm
	 *            the signature algorithm that belongs to it
	 * @throws Exception
	 *             if key generation or certification fails
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, 2048, SHA256withRSA", "DSA, 2048, SHA256withDSA", "EC, 0, SHA256withECDSA",
			"Ed25519, 0, Ed25519", "ML-DSA-44, 0, ML-DSA-44", "ML-DSA-65, 0, ML-DSA-65",
			"ML-DSA-87, 0, ML-DSA-87" })
	void everyEntryPointCertifiesEveryKey(final String algorithm, final int size,
		final String signatureAlgorithm) throws Exception
	{
		KeyPair keyPair = newKeyPair(algorithm, size);
		Date notBefore = new Date(0L);
		Date notAfter = new Date(2_000_000_000_000L);

		X509Certificate byDays = CertFactory.newX509CertificateV3(keyPair, NAME, 365, NAME,
			signatureAlgorithm);
		X509Certificate byDates = CertFactory.newX509CertificateV3(keyPair, NAME, BigInteger.ONE,
			notBefore, notAfter, NAME, signatureAlgorithm);
		X509Certificate version1 = CertFactory.newX509CertificateV1(keyPair, NAME, BigInteger.ONE,
			notBefore, notAfter, NAME, signatureAlgorithm);

		assertNotNull(byDays, algorithm + " must be certifiable by the days entry point");
		assertNotNull(byDates, algorithm + " must be certifiable by the dated entry point");
		assertNotNull(version1, algorithm + " must be certifiable by the v1 entry point");
		assertDoesNotThrow(() -> byDays.verify(keyPair.getPublic()),
			algorithm + " must produce a certificate its own key verifies");
	}
}
