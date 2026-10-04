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

import java.io.File;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * Parameterized tests for
 * {@link CertificateExtensions#getFirstValueOf(X509Certificate, ASN1ObjectIdentifier)}
 */
class CertificateExtensionsFirstValueOfParameterizedTest
{

	private static X509Certificate certificate;

	/**
	 * One attribute lookup on the subject of the certificate
	 *
	 * @param style
	 *            the attribute type
	 * @param expected
	 *            the expected first value, empty if the subject has no such attribute
	 */
	record FirstValueCase(ASN1ObjectIdentifier style, String expected) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		// the subject of this certificate is "CN=Test subject" and nothing else
		certificate = CertificateReader.readPemCertificate(new File(pemDir, "certificate.pem"));
	}

	static Stream<FirstValueCase> firstValueCases()
	{
		return Stream.of(new FirstValueCase(BCStyle.CN, "Test subject"),
			new FirstValueCase(BCStyle.OU, ""), new FirstValueCase(BCStyle.O, ""),
			new FirstValueCase(BCStyle.L, ""), new FirstValueCase(BCStyle.ST, ""),
			new FirstValueCase(BCStyle.C, ""));
	}

	/**
	 * Test method for
	 * {@link CertificateExtensions#getFirstValueOf(X509Certificate, ASN1ObjectIdentifier)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the certificate cannot be encoded
	 */
	@ParameterizedTest
	@MethodSource("firstValueCases")
	void getFirstValueOf(final FirstValueCase testCase) throws Exception
	{
		assertEquals(testCase.expected(),
			CertificateExtensions.getFirstValueOf(certificate, testCase.style()));
	}
}
