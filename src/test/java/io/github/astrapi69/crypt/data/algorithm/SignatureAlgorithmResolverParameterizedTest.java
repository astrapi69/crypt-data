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
package io.github.astrapi69.crypt.data.algorithm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.factory.CertificateTestDataFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.key.KeySizeInitializer;
import io.github.astrapi69.crypt.data.model.CertificateInfo;

/**
 * Fast parameterized tests for {@link SignatureAlgorithmResolver}. The brute-force key-size probing
 * is driven through {@link KeySizeProbe} so that exactly one key pair is generated per run instead
 * of one per registered key pair algorithm and key size
 */
class SignatureAlgorithmResolverParameterizedTest
{

	/** Strong reference so the level override is not lost to logger garbage collection */
	private static final Logger RESOLVER_LOGGER = Logger
		.getLogger(SignatureAlgorithmResolver.class.getName());

	private static final Map<String, KeyPair> KEY_PAIRS = new HashMap<>();

	private static Level previousLevel;

	/**
	 * One combination of key pair algorithm and signature algorithm with the expected validity
	 *
	 * @param keyPairAlgorithm
	 *            the algorithm of the key pair used to sign the certificate
	 * @param signatureAlgorithm
	 *            the signature algorithm under test
	 * @param expectedValid
	 *            whether a certificate can be created with this combination
	 */
	record CertificateSignatureCase(String keyPairAlgorithm, String signatureAlgorithm,
		boolean expectedValid) {
	}

	/**
	 * One run of the resolver where the key-size probe accepts a single algorithm and key size
	 *
	 * @param acceptedKeyPairAlgorithm
	 *            the only key pair algorithm the probe reports as supported
	 * @param acceptedKeySize
	 *            the only key size the probe reports as supported
	 * @param expectedKeyPairAlgorithms
	 *            the key set the resolver must return
	 * @param expectedSupported
	 *            a signature algorithm that must be reported for the accepted key pair algorithm or
	 *            null if nothing is expected
	 * @param expectedUnsupported
	 *            a signature algorithm that must not be reported or null if nothing is expected
	 */
	record ResolverCase(String acceptedKeyPairAlgorithm, int acceptedKeySize,
		Set<String> expectedKeyPairAlgorithms, String expectedSupported,
		String expectedUnsupported) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		previousLevel = RESOLVER_LOGGER.getLevel();
		// the resolver logs every rejected combination together with its stack trace; keep the
		// test output readable
		RESOLVER_LOGGER.setLevel(Level.SEVERE);
		KEY_PAIRS.put("EC", newKeyPair("EC", 256));
		KEY_PAIRS.put("RSA", newKeyPair("RSA", 1024));
	}

	@AfterAll
	static void tearDown()
	{
		RESOLVER_LOGGER.setLevel(previousLevel);
	}

	private static KeyPair newKeyPair(final String algorithm, final int keySize) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		generator.initialize(keySize);
		return generator.generateKeyPair();
	}

	static Stream<CertificateSignatureCase> certificateSignatureCases()
	{
		return Stream.of(new CertificateSignatureCase("EC", "SHA256withECDSA", true),
			new CertificateSignatureCase("EC", "SHA384withECDSA", true),
			new CertificateSignatureCase("RSA", "SHA256withRSA", true),
			new CertificateSignatureCase("RSA", "SHA1withRSA", true),
			// key type and signature family do not match: the signer cannot be created
			new CertificateSignatureCase("EC", "SHA256withRSA", false),
			new CertificateSignatureCase("RSA", "SHA256withECDSA", false),
			// signature name unknown to the provider: rejected as illegal argument
			new CertificateSignatureCase("RSA", "NoSuchSignatureAlgorithm", false),
			new CertificateSignatureCase("EC", "SHA256withFOO", false));
	}

	/**
	 * Test method for
	 * {@link SignatureAlgorithmResolver#isAlgorithmValidForCertificate(CertificateInfo)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("certificateSignatureCases")
	void isAlgorithmValidForCertificate(final CertificateSignatureCase testCase)
	{
		CertificateInfo certificateInfo = newCertificateInfo(testCase.keyPairAlgorithm(),
			testCase.signatureAlgorithm());

		boolean actual = SignatureAlgorithmResolver.isAlgorithmValidForCertificate(certificateInfo);

		assertEquals(testCase.expectedValid(), actual, testCase.toString());
		// the check is a pure function of its input
		assertEquals(actual,
			SignatureAlgorithmResolver.isAlgorithmValidForCertificate(certificateInfo));
	}

	static Stream<ResolverCase> resolverCases()
	{
		return Stream.of(
			new ResolverCase("EC", 256, Set.of("EC"), "SHA256WITHECDSA", "SHA256WITHRSA"),
			new ResolverCase("NoSuchKeyPairAlgorithm", 256, Set.of(), null, null),
			// SM2 key pairs are generated by BC but the key cannot be read back through a
			// KeyFactory, so every certificate attempt fails with a RuntimeException: the resolver
			// must swallow it and simply report no supported signature algorithm
			new ResolverCase("SM2", 256, Set.of(), null, null));
	}

	/**
	 * Test method for
	 * {@link SignatureAlgorithmResolver#getSupportedSignatureAlgorithms(String, Class, KeySizeInitializer, int, int, int)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the resolver fails
	 */
	@ParameterizedTest
	@MethodSource("resolverCases")
	void getSupportedSignatureAlgorithms(final ResolverCase testCase) throws Exception
	{
		Map<String, Set<String>> actual = SignatureAlgorithmResolver
			.getSupportedSignatureAlgorithms("KeyPairGenerator", KeySizeProbe.class,
				KeySizeProbe.accepting(testCase.acceptedKeyPairAlgorithm(),
					testCase.acceptedKeySize()),
				testCase.acceptedKeySize(), testCase.acceptedKeySize(), 1);

		assertNotNull(actual);
		assertEquals(testCase.expectedKeyPairAlgorithms(), actual.keySet());
		if (testCase.expectedSupported() != null)
		{
			Set<String> signatureAlgorithms = actual.get(testCase.acceptedKeyPairAlgorithm());
			assertTrue(signatureAlgorithms.contains(testCase.expectedSupported()),
				signatureAlgorithms.toString());
			assertFalse(signatureAlgorithms.contains(testCase.expectedUnsupported()),
				signatureAlgorithms.toString());
			// every reported signature algorithm is a registered "Signature" service
			assertTrue(
				AlgorithmExtensions.getAlgorithms("Signature").containsAll(signatureAlgorithms));
		}
	}

	private static CertificateInfo newCertificateInfo(final String keyPairAlgorithm,
		final String signatureAlgorithm)
	{
		KeyPair keyPair = KEY_PAIRS.get(keyPairAlgorithm);
		return CertificateInfo.builder()
			.privateKeyInfo(KeyInfoExtensions.toKeyInfo(keyPair.getPrivate()))
			.publicKeyInfo(KeyInfoExtensions.toKeyInfo(keyPair.getPublic()))
			.issuer(CertificateTestDataFactory.newIssuerDistinguishedNameInfo())
			.subject(CertificateTestDataFactory.newSubjectDistinguishedNameInfo())
			.serial(BigInteger.TEN).validity(CertificateTestDataFactory.newValidity())
			.signatureAlgorithm(signatureAlgorithm).version(3)
			.extensions(CertificateTestDataFactory.newExtensionInfos()).build();
	}
}
