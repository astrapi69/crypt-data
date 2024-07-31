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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;

/**
 * The unit test class for the class {@link CertFactory}
 */
public class CertFactoryParameterizedTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Parameterized test method for
	 * {@link CertFactory#newX509CertificateV1(KeyPair, X500Name, BigInteger, Date, Date, X500Name, String)}
	 * using data from a CSV file
	 *
	 * @param issuer
	 *            the issuer
	 * @param serial
	 *            the serial number
	 * @param notBefore
	 *            date before which the certificate is not valid
	 * @param notAfter
	 *            date after which the certificate is not valid
	 * @param subject
	 *            the subject
	 * @param signatureAlgorithm
	 *            the signature algorithm
	 * @throws Exception
	 *             if an error occurs during certificate creation
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/cert_data.csv", numLinesToSkip = 1)
	public void testNewX509CertificateV1_Parameterized(String issuer, String serial,
		String notBefore, String notAfter, String subject, String signatureAlgorithm)
		throws Exception
	{
		KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);

		X500Name issuerName = new X500Name(issuer);
		BigInteger serialNumber = new BigInteger(serial);
		Date notBeforeDate = Date
			.from(LocalDate.parse(notBefore).atStartOfDay(ZoneId.systemDefault()).toInstant());
		Date notAfterDate = Date
			.from(LocalDate.parse(notAfter).atStartOfDay(ZoneId.systemDefault()).toInstant());
		X500Name subjectName = new X500Name(subject);

		X509Certificate cert = CertFactory.newX509CertificateV1(keyPair, issuerName, serialNumber,
			notBeforeDate, notAfterDate, subjectName, signatureAlgorithm);
		assertNotNull(cert);
	}
}
