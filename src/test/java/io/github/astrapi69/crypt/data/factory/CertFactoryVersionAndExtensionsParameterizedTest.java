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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.model.CertificateInfo;
import io.github.astrapi69.crypt.data.model.ExtensionInfo;

/**
 * Parameterized tests for the extension handling of the {@link CertFactory} version 3 factory
 * methods and for the version selection of {@link CertFactory#newX509Certificate(CertificateInfo)}
 */
class CertFactoryVersionAndExtensionsParameterizedTest
{

	private static final X500Name ISSUER = new X500Name("CN=Test Issuer");
	private static final X500Name SUBJECT = new X500Name("CN=Test Subject");
	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

	private static KeyPair keyPair;

	/**
	 * One set of extensions
	 *
	 * @param description
	 *            what is passed
	 * @param extensions
	 *            the extensions, may be null
	 * @param expectedCritical
	 *            the number of critical extensions the certificate must carry
	 * @param expectedNonCritical
	 *            the number of non-critical extensions the certificate must carry
	 */
	record ExtensionsCase(String description, Extension[] extensions, int expectedCritical,
		int expectedNonCritical) {
	}

	/**
	 * One requested certificate version
	 *
	 * @param version
	 *            the requested version, may be null
	 * @param expectedCertificateVersion
	 *            the version of the created certificate
	 */
	record VersionCase(Integer version, int expectedCertificateVersion) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 1024);
	}

	private static Extension newExtension(final String oid, final boolean critical,
		final String value)
	{
		return ExtensionInfo.toExtension(
			ExtensionInfo.builder().extensionId(oid).critical(critical).value(value).build());
	}

	private static int size(final Set<String> extensionOids)
	{
		return extensionOids == null ? 0 : extensionOids.size();
	}

	static Stream<ExtensionsCase> extensionsCases()
	{
		return Stream.of(new ExtensionsCase("null extensions", null, 0, 0),
			new ExtensionsCase("no extensions", new Extension[0], 0, 0),
			new ExtensionsCase("one critical extension",
				new Extension[] { newExtension("1.2.3.4.5.6.7", true, "critical") }, 1, 0),
			new ExtensionsCase("critical and non-critical extension",
				new Extension[] { newExtension("1.2.3.4.5.6.7", true, "critical"),
						newExtension("1.2.3.4.5.6.8", false, "plain") },
				1, 1));
	}

	/**
	 * Test method for
	 * {@link CertFactory#newX509CertificateV3(KeyPair, X500Name, int, X500Name, String, Extension...)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the certificate cannot be created or verified
	 */
	@ParameterizedTest
	@MethodSource("extensionsCases")
	void newX509CertificateV3FromKeyPair(final ExtensionsCase testCase) throws Exception
	{
		X509Certificate actual = CertFactory.newX509CertificateV3(keyPair, ISSUER, 30, SUBJECT,
			SIGNATURE_ALGORITHM, testCase.extensions());

		assertCertificate(actual, testCase);
	}

	/**
	 * Test method for
	 * {@link CertFactory#newX509CertificateV3(java.security.PrivateKey, java.security.PublicKey, X500Name, BigInteger, Date, Date, X500Name, String, Extension...)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the certificate cannot be created or verified
	 */
	@ParameterizedTest
	@MethodSource("extensionsCases")
	void newX509CertificateV3FromKeys(final ExtensionsCase testCase) throws Exception
	{
		Date notBefore = new Date();
		Date notAfter = new Date(notBefore.getTime() + 86_400_000L);

		X509Certificate actual = CertFactory.newX509CertificateV3(keyPair.getPrivate(),
			keyPair.getPublic(), ISSUER, BigInteger.valueOf(42), notBefore, notAfter, SUBJECT,
			SIGNATURE_ALGORITHM, testCase.extensions());

		assertCertificate(actual, testCase);
		assertEquals(BigInteger.valueOf(42), actual.getSerialNumber());
	}

	private static void assertCertificate(final X509Certificate certificate,
		final ExtensionsCase testCase) throws Exception
	{
		assertEquals(3, certificate.getVersion(), testCase.description());
		assertEquals(SUBJECT.toString(), certificate.getSubjectX500Principal().getName());
		assertEquals(ISSUER.toString(), certificate.getIssuerX500Principal().getName());
		assertEquals(testCase.expectedCritical(), size(certificate.getCriticalExtensionOIDs()),
			testCase.description());
		assertEquals(testCase.expectedNonCritical(),
			size(certificate.getNonCriticalExtensionOIDs()), testCase.description());
		// the certificate is signed with the private key of the pair
		certificate.verify(keyPair.getPublic());
	}

	static Stream<VersionCase> versionCases()
	{
		return Stream.of(new VersionCase(null, 1), new VersionCase(1, 1), new VersionCase(3, 3));
	}

	/**
	 * Test method for {@link CertFactory#newX509Certificate(CertificateInfo)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the certificate cannot be created or verified
	 */
	@ParameterizedTest
	@MethodSource("versionCases")
	void newX509CertificateFromCertificateInfo(final VersionCase testCase) throws Exception
	{
		CertificateInfo certificateInfo = CertificateInfo.builder()
			.privateKeyInfo(KeyInfoExtensions.toKeyInfo(keyPair.getPrivate()))
			.publicKeyInfo(KeyInfoExtensions.toKeyInfo(keyPair.getPublic()))
			.issuer(CertificateTestDataFactory.newIssuerDistinguishedNameInfo())
			.subject(CertificateTestDataFactory.newSubjectDistinguishedNameInfo())
			.serial(BigInteger.TEN).validity(CertificateTestDataFactory.newValidity())
			.signatureAlgorithm(SIGNATURE_ALGORITHM).version(testCase.version())
			.extensions(CertificateTestDataFactory.newExtensionInfos()).build();

		X509Certificate actual = CertFactory.newX509Certificate(certificateInfo);

		assertEquals(testCase.expectedCertificateVersion(), actual.getVersion());
		assertEquals(BigInteger.TEN, actual.getSerialNumber());
		// only version 3 certificates carry the extensions
		assertEquals(testCase.expectedCertificateVersion() == 3 ? 1 : 0,
			size(actual.getCriticalExtensionOIDs()));
		actual.verify(keyPair.getPublic());
	}
}
