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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for the validity arithmetic of
 * {@link CertFactory#newX509CertificateV3(KeyPair, X500Name, int, X500Name, String, Extension...)}
 * and the basic constraints written by
 * {@link CertFactory#newIntermediateX509CertificateV3(KeyPair, X500Name, BigInteger, Date, Date, X500Name, String, X509Certificate)}
 * and
 * {@link CertFactory#newEndEntityX509CertificateV3(KeyPair, X500Name, BigInteger, Date, Date, X500Name, String, X509Certificate)}
 */
class CertFactoryValidityAndBasicConstraintsParameterizedTest
{

	private static final long MILLIS_PER_DAY = 86_400_000L;
	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	private static final X500Name ISSUER = new X500Name("CN=Test CA");
	private static final X500Name SUBJECT = new X500Name("CN=Test Subject");

	private static KeyPair keyPair;
	private static X509Certificate caCertificate;

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		keyPair = generator.generateKeyPair();
		caCertificate = CertFactory.newX509CertificateV3(keyPair, ISSUER, 1, ISSUER,
			SIGNATURE_ALGORITHM);
	}

	/**
	 * One validity period in days
	 *
	 * @param daysToBeValid
	 *            the number of days the certificate is valid
	 */
	record ValidityCase(int daysToBeValid) {
	}

	/**
	 * One certificate kind with the basic constraints it must carry
	 *
	 * @param description
	 *            the kind of certificate
	 * @param intermediate
	 *            whether an intermediate (CA, path length 0) certificate is requested
	 * @param expectedBasicConstraints
	 *            the expected value of {@link X509Certificate#getBasicConstraints()}
	 */
	record BasicConstraintsCase(String description, boolean intermediate,
		int expectedBasicConstraints) {
	}

	static Stream<ValidityCase> validityCases()
	{
		return Stream.of(new ValidityCase(1), new ValidityCase(30), new ValidityCase(365));
	}

	static Stream<BasicConstraintsCase> basicConstraintsCases()
	{
		return Stream.of(new BasicConstraintsCase("intermediate CA, path length 0", true, 0),
			new BasicConstraintsCase("end entity, not a CA", false, -1));
	}

	/**
	 * Test method for
	 * {@link CertFactory#newX509CertificateV3(KeyPair, X500Name, int, X500Name, String, Extension...)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the certificate cannot be created
	 */
	@ParameterizedTest
	@MethodSource("validityCases")
	void validityPeriodIsExactlyTheRequestedDays(final ValidityCase testCase) throws Exception
	{
		long before = System.currentTimeMillis();
		X509Certificate certificate = CertFactory.newX509CertificateV3(keyPair, ISSUER,
			testCase.daysToBeValid(), SUBJECT, SIGNATURE_ALGORITHM);
		long after = System.currentTimeMillis();

		long notBefore = certificate.getNotBefore().getTime();
		long notAfter = certificate.getNotAfter().getTime();
		// X.509 stores seconds, so compare with second precision
		assertEquals(testCase.daysToBeValid() * MILLIS_PER_DAY / 1000,
			(notAfter - notBefore) / 1000, testCase.toString());
		assertTrue(before / 1000 <= notBefore / 1000 && notBefore / 1000 <= after / 1000,
			"notBefore must be now");
		assertEquals(new BigInteger(Long.toString(notBefore)).divide(BigInteger.valueOf(1000)),
			certificate.getSerialNumber().divide(BigInteger.valueOf(1000)),
			"serial is the creation timestamp");
	}

	/**
	 * Test method for
	 * {@link CertFactory#newIntermediateX509CertificateV3(KeyPair, X500Name, BigInteger, Date, Date, X500Name, String, X509Certificate)}
	 * and
	 * {@link CertFactory#newEndEntityX509CertificateV3(KeyPair, X500Name, BigInteger, Date, Date, X500Name, String, X509Certificate)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the certificate cannot be created
	 */
	@ParameterizedTest
	@MethodSource("basicConstraintsCases")
	void basicConstraintsMatchCertificateKind(final BasicConstraintsCase testCase) throws Exception
	{
		Date notBefore = new Date();
		Date notAfter = new Date(notBefore.getTime() + MILLIS_PER_DAY);
		BigInteger serial = BigInteger.valueOf(42);

		X509Certificate certificate = testCase.intermediate()
			? CertFactory.newIntermediateX509CertificateV3(keyPair, ISSUER, serial, notBefore,
				notAfter, SUBJECT, SIGNATURE_ALGORITHM, caCertificate)
			: CertFactory.newEndEntityX509CertificateV3(keyPair, ISSUER, serial, notBefore,
				notAfter, SUBJECT, SIGNATURE_ALGORITHM, caCertificate);

		assertEquals(testCase.expectedBasicConstraints(), certificate.getBasicConstraints(),
			testCase.description());
		assertNotNull(certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
		assertNotNull(certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId()));
		assertEquals(serial, certificate.getSerialNumber());
		certificate.verify(keyPair.getPublic());
	}
}
