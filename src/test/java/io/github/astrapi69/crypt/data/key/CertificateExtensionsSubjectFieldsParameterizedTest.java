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
package io.github.astrapi69.crypt.data.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.factory.CertFactory;

/**
 * Parameterized test for the subject field accessors of {@link CertificateExtensions} on a
 * certificate whose subject actually carries the fields
 */
class CertificateExtensionsSubjectFieldsParameterizedTest
{

	private static final X500Name ISSUER = new X500Name("C=GB,L=London,O=Issuer Ltd,CN=Issuer");
	private static final X500Name SUBJECT = new X500Name(
		"C=DE,L=Berlin,O=Example Org,OU=Dev,CN=Example Subject");

	private static X509Certificate certificate;

	/**
	 * A field accessor of {@link CertificateExtensions} together with its expected value
	 */
	@FunctionalInterface
	interface FieldAccessor
	{
		String get(X509Certificate certificate) throws CertificateEncodingException;
	}

	/**
	 * One subject field
	 *
	 * @param field
	 *            the name of the field
	 * @param accessor
	 *            the accessor under test
	 * @param expected
	 *            the expected value
	 */
	record SubjectFieldCase(String field, FieldAccessor accessor, String expected) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		KeyPair keyPair = generator.generateKeyPair();
		certificate = CertFactory.newX509CertificateV3(keyPair, ISSUER, 1, SUBJECT,
			"SHA256withRSA");
	}

	static Stream<SubjectFieldCase> subjectFieldCases()
	{
		return Stream.of(new SubjectFieldCase("country", CertificateExtensions::getCountry, "DE"),
			new SubjectFieldCase("locality", CertificateExtensions::getLocality, "Berlin"),
			new SubjectFieldCase("organization", CertificateExtensions::getOrganization,
				"Example Org"),
			new SubjectFieldCase("common name",
				cert -> CertificateExtensions.getFirstValueOf(cert, BCStyle.CN), "Example Subject"),
			new SubjectFieldCase("organization unit",
				cert -> CertificateExtensions.getFirstValueOf(cert, BCStyle.OU), "Dev"),
			new SubjectFieldCase("absent state",
				cert -> CertificateExtensions.getFirstValueOf(cert, BCStyle.ST), ""));
	}

	/**
	 * Test method for the subject field accessors of {@link CertificateExtensions}
	 *
	 * @param testCase
	 *            the test case
	 * @throws CertificateEncodingException
	 *             if the certificate cannot be encoded
	 */
	@ParameterizedTest
	@MethodSource("subjectFieldCases")
	void subjectFieldIsReadFromTheSubject(final SubjectFieldCase testCase)
		throws CertificateEncodingException
	{
		assertEquals(testCase.expected(), testCase.accessor().get(certificate), testCase.field());
	}

	/**
	 * Test method for {@link CertificateExtensions#getSubject(X509Certificate)},
	 * {@link CertificateExtensions#getIssuedBy(X509Certificate)} and
	 * {@link CertificateExtensions#getIssuedTo(X509Certificate)}
	 */
	@Test
	void subjectAndIssuerNamesComeFromTheRightPrincipal()
	{
		String subject = CertificateExtensions.getSubject(certificate);

		assertEquals(certificate.getSubjectX500Principal().getName(), subject);
		assertEquals(CertificateExtensions.getIssuedBy(certificate), subject);
		assertTrue(subject.contains("CN=Example Subject"), subject);
		assertTrue(subject.contains("L=Berlin"), subject);

		String issuedTo = CertificateExtensions.getIssuedTo(certificate);
		assertEquals(certificate.getIssuerX500Principal().getName(), issuedTo);
		assertTrue(issuedTo.contains("CN=Issuer"), issuedTo);
	}
}
