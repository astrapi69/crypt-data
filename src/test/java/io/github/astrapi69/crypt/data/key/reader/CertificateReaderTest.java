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
package io.github.astrapi69.crypt.data.key.reader;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.UnionWord;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.key.writer.CertificateWriter;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.number.RandomBigIntegerFactory;

/**
 * The unit test class for the class {@link CertificateReaderTest}
 */
public class CertificateReaderTest
{
	File derDir;
	File certificateDerFile;
	File privatekeyPemDir;
	File privatekeyPemFile;
	PrivateKey privateKey;
	File publickeyPemDir;
	File publickeyPemFile;
	File certificateFile;
	PublicKey publicKey;
	String subject;
	String issuer;
	String signatureAlgorithm;
	Date start;
	Date end;
	BigInteger serialNumber;
	X509Certificate cert;
	X509Certificate certificate;
	File pemDir;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if any errors occurs by initialize the test data
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		certificateDerFile = new File(derDir, "certificate.der");

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");

		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privatekeyPemFile = new File(privatekeyPemDir, "private.pem");


		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");

		privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		subject = "CN=Test subject";
		issuer = "CN=Test issue";
		signatureAlgorithm = HashAlgorithm.SHA256.getAlgorithm() + UnionWord.With.name()
			+ KeyPairGeneratorAlgorithm.RSA.getAlgorithm();

		start = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		end = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		serialNumber = RandomBigIntegerFactory.randomSerialNumber();
		// create certificate
		cert = CertFactory.newX509Certificate(publicKey, privateKey, serialNumber, subject, issuer,
			signatureAlgorithm, start, end);
		assertNotNull(cert);
	}

	/**
	 * Test method for {@link CertificateReader#readCertificate(File)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadDerCertificateFile() throws Exception
	{

		// new scenario...
		// save it ...
		CertificateWriter.write(cert, certificateDerFile, KeyFileFormat.DER);

		certificate = CertificateReader.readCertificate(certificateDerFile);
		assertNotNull(certificate);

		DeleteFileExtensions.delete(certificateDerFile);
	}

	/**
	 * Test method for {@link CertificateReader#readPemCertificate(File)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadPemCertificateFile() throws Exception
	{

		certificateFile = new File(pemDir, "certificate.cert");
		// save it ...
		CertificateWriter.write(cert, certificateFile, KeyFileFormat.PEM);

		certificate = CertificateReader.readPemCertificate(certificateFile);
		assertNotNull(certificate);

		DeleteFileExtensions.delete(certificateFile);
	}

	/**
	 * Test method for {@link CertificateReader} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CertificateReader.class);
	}

}
