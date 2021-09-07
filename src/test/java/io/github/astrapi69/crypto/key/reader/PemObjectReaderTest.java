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
package io.github.astrapi69.crypto.key.reader;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.util.io.pem.PemObject;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import io.github.astrapi69.search.PathFinder;


/**
 * The unit test class for the class {@link PemObjectReader}
 */
public class PemObjectReaderTest
{

	/**
	 * Test method for {@link PemObjectReader#getPemObject(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetPemObject() throws IOException
	{
		String actual;
		String expected;
		File privatekeyPemDir;
		File rsaPrivatekeyPemFile;
		File privatekey2PemFile;
		PemObject pemObject;
		File rsaPublickeyFile;
		File publickeyFile;
		File dsaPPPrivatekeyFile;
		File rsaPPPrivatekeyFile;
		File crlCertFile;
		File crtCertFile;
		File csrCertFile;
		File newCsrCertFile;
		File pkcs7File;
		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");

		// new scenario...
		rsaPrivatekeyPemFile = new File(privatekeyPemDir, "private.pem");
		pemObject = PemObjectReader.getPemObject(rsaPrivatekeyPemFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.RSA_PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		// new scenario...
		privatekey2PemFile = new File(privatekeyPemDir, "private2.pem");
		pemObject = PemObjectReader.getPemObject(privatekey2PemFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		// new scenario...
		rsaPublickeyFile = new File(privatekeyPemDir, "rsa-public-key.pem");
		pemObject = PemObjectReader.getPemObject(rsaPublickeyFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.RSA_PUBLIC_KEY_NAME;
		assertEquals(expected, actual);
		// new scenario...
		publickeyFile = new File(privatekeyPemDir, "public.pem");
		pemObject = PemObjectReader.getPemObject(publickeyFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.PUBLIC_KEY_NAME;
		assertEquals(expected, actual);
		// new scenario...
		dsaPPPrivatekeyFile = new File(privatekeyPemDir, "dsa-pwp-pk-pw-is-123456.pem");
		pemObject = PemObjectReader.getPemObject(dsaPPPrivatekeyFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.DSA_PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		// new scenario...
		rsaPPPrivatekeyFile = new File(privatekeyPemDir, "rsa-pwp-pk-pw-is-123456.pem");
		pemObject = PemObjectReader.getPemObject(rsaPPPrivatekeyFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.RSA_PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		// new scenario...
		crlCertFile = new File(privatekeyPemDir, "crl-cert.pem");
		pemObject = PemObjectReader.getPemObject(crlCertFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.X509_CRL_NAME;
		assertEquals(expected, actual);
		// new scenario...
		crtCertFile = new File(privatekeyPemDir, "certificate.pem");
		pemObject = PemObjectReader.getPemObject(crtCertFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.CERTIFICATE_NAME;
		assertEquals(expected, actual);
		// new scenario...
		csrCertFile = new File(privatekeyPemDir, "csr-cert.pem");
		pemObject = PemObjectReader.getPemObject(csrCertFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.CERTIFICATE_REQUEST_NAME;
		assertEquals(expected, actual);
		// new scenario...
		newCsrCertFile = new File(privatekeyPemDir, "new-csr-cert.pem");
		pemObject = PemObjectReader.getPemObject(newCsrCertFile);
		actual = pemObject.getType();
		expected = KeyStringEntry.NEW_CERTIFICATE_REQUEST_NAME;
		assertEquals(expected, actual);
		// new scenario...
		pkcs7File = new File(privatekeyPemDir, "pkcs7.pem");
		pemObject = PemObjectReader.getPemObject(pkcs7File);
		actual = pemObject.getType();
		expected = KeyStringEntry.PKCS7_KEY_NAME;
		assertEquals(expected, actual);

	}

	/**
	 * Test method for {@link PemObjectReader#readPemPrivateKey(File, String)} you can create the
	 * file id_rsa with following command: ssh-keygen -t rsa -b 4096 -f ~/.ssh-tmp/id_rsa
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testReadPemPrivateKey() throws IOException
	{
		File privatekeyPemDir;
		File privatekeyPemFile;
		PrivateKey privateKey;
		// new scenario...
		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privatekeyPemFile = new File(privatekeyPemDir, "id_rsa");

		privateKey = PemObjectReader.readPemPrivateKey(privatekeyPemFile, "secret");
		assertNotNull(privateKey);
		// new scenario...
		privatekeyPemFile = new File(privatekeyPemDir, "test.key");

		privateKey = PemObjectReader.readPemPrivateKey(privatekeyPemFile, "bosco");
		assertNotNull(privateKey);
	}

	/**
	 * Test method for {@link PemObjectReader#toPemFormat(PemObject)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testToPemFormat() throws IOException
	{
		String actual;
		File privatekeyPemDir;
		File privatekeyPemFile;
		PemObject pemObject;

		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		pemObject = PemObjectReader.getPemObject(privatekeyPemFile);
		actual = PemObjectReader.toPemFormat(pemObject);
		System.out.println(actual);
	}

	/**
	 * Test method for {@link PemObjectReader} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PemObjectReader.class);
	}

}
