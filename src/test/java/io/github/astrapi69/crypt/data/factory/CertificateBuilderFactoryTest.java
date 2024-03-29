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

import java.io.File;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.date.CalculateDateExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.number.RandomBigIntegerFactory;

/**
 * The unit test class for the class {@link CertificateBuilderFactory}
 */
public class CertificateBuilderFactoryTest
{

	/**
	 * Test method for
	 * {@link CertificateBuilderFactory#newX509v1CertificateBuilder(X500Name, BigInteger, Date, Date, X500Name, PublicKey)}
	 */
	@Test
	public void testNewX509v1CertificateBuilder() throws Exception
	{
		File keyPemDir;
		File publickeyPemFile;
		PublicKey publicKey;
		X500Name issuer;
		BigInteger serial;
		Date notBefore;
		Date notAfter;
		X500Name subject;
		X509v1CertificateBuilder certificateBuilder;

		keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		issuer = new X500Name("C=DE");
		serial = RandomBigIntegerFactory.randomSerialNumber();

		notBefore = new Date();
		notAfter = CalculateDateExtensions.addYears(notBefore, 10);
		subject = new X500Name("O=foo-company");

		certificateBuilder = CertificateBuilderFactory.newX509v1CertificateBuilder(issuer, serial,
			notBefore, notAfter, subject, publicKey);

		assertNotNull(certificateBuilder);
	}

	/**
	 * Test method for
	 * {@link CertificateBuilderFactory#newX509v3CertificateBuilder(X500Name, BigInteger, Date, Date, X500Name, SubjectPublicKeyInfo)}
	 */
	@Test
	public void testNewX509v3CertificateBuilder() throws Exception
	{
		File keyPemDir;
		File publickeyPemFile;
		PublicKey publicKey;
		X500Name issuer;
		BigInteger serial;
		Date notBefore;
		Date notAfter;
		X500Name subject;
		SubjectPublicKeyInfo publicKeyInfo;
		X509v3CertificateBuilder certificateBuilder;

		keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		issuer = new X500Name("C=DE");
		serial = RandomBigIntegerFactory.randomSerialNumber();

		notBefore = new Date();
		notAfter = CalculateDateExtensions.addYears(notBefore, 10);
		subject = new X500Name("O=foo-company");

		publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

		certificateBuilder = CertificateBuilderFactory.newX509v3CertificateBuilder(issuer, serial,
			notBefore, notAfter, subject, publicKeyInfo);

		assertNotNull(certificateBuilder);
	}

	/**
	 * Test method for {@link CertificateBuilderFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CertificateBuilderFactory.class);
	}

}
