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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensionsTest;
import io.github.astrapi69.file.search.PathFinder;


/**
 * The unit test class for the class {@link PemObjectReader}
 */
public class PemObjectReaderTest
{

	File pemDir;
	File derDir;
	File privateKeyDerFile;
	PemObject pemObject;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");
	}

	/**
	 * Test method for {@link PemObjectReader#getPemObject(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetPemObjectOnDerFile() throws IOException
	{
		pemObject = PemObjectReader.getPemObject(privateKeyDerFile);
		assertNull(pemObject);
		pemObject = PemObjectReader.getPemObject(new File(pemDir, "test.txt"));
		assertNull(pemObject);
	}

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
		File rsaPrivatekeyPemFile;
		File privatekey2PemFile;
		File rsaPublickeyFile;
		File publickeyFile;
		File dsaPPPrivatekeyFile;
		File rsaPPPrivatekeyFile;
		File crlCertFile;
		File crtCertFile;
		File csrCertFile;
		File newCsrCertFile;
		File pkcs7File;

		// new scenario...
		rsaPrivatekeyPemFile = new File(pemDir, "private.pem");
		assertTrue(PemObjectReader.isPemObject(rsaPrivatekeyPemFile));
		pemObject = PemObjectReader.getPemObject(rsaPrivatekeyPemFile);
		actual = pemObject.getType();
		expected = PemType.RSA_PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.RSA_PRIVATE_KEY, PemObjectReader.getPemType(pemObject));

		// new scenario...
		privatekey2PemFile = new File(pemDir, "private2.pem");
		assertTrue(PemObjectReader.isPemObject(privatekey2PemFile));
		pemObject = PemObjectReader.getPemObject(privatekey2PemFile);
		actual = pemObject.getType();
		expected = PemType.PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.PRIVATE_KEY, PemObjectReader.getPemType(pemObject));
		// new scenario...
		rsaPublickeyFile = new File(pemDir, "rsa-public-key.pem");
		pemObject = PemObjectReader.getPemObject(rsaPublickeyFile);
		actual = pemObject.getType();
		expected = PemType.RSA_PUBLIC_KEY_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.RSA_PUBLIC_KEY, PemObjectReader.getPemType(pemObject));
		// new scenario...
		publickeyFile = new File(pemDir, "public.pem");
		pemObject = PemObjectReader.getPemObject(publickeyFile);
		actual = pemObject.getType();
		expected = PemType.PUBLIC_KEY_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.PUBLIC_KEY, PemObjectReader.getPemType(pemObject));
		// new scenario...
		dsaPPPrivatekeyFile = new File(pemDir, "dsa-pwp-pk-pw-is-123456.pem");
		pemObject = PemObjectReader.getPemObject(dsaPPPrivatekeyFile);
		actual = pemObject.getType();
		expected = PemType.DSA_PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.DSA_PRIVATE_KEY, PemObjectReader.getPemType(pemObject));
		// new scenario...
		rsaPPPrivatekeyFile = new File(pemDir, "rsa-pwp-pk-pw-is-123456.pem");
		pemObject = PemObjectReader.getPemObject(rsaPPPrivatekeyFile);
		actual = pemObject.getType();
		expected = PemType.RSA_PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.RSA_PRIVATE_KEY, PemObjectReader.getPemType(pemObject));
		// new scenario...
		crlCertFile = new File(pemDir, "crl-cert.pem");
		pemObject = PemObjectReader.getPemObject(crlCertFile);
		actual = pemObject.getType();
		expected = PemType.X509_CRL_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.X509_CRL, PemObjectReader.getPemType(pemObject));
		// new scenario...
		crtCertFile = new File(pemDir, "certificate.pem");
		pemObject = PemObjectReader.getPemObject(crtCertFile);
		actual = pemObject.getType();
		expected = PemType.CERTIFICATE_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.CERTIFICATE, PemObjectReader.getPemType(pemObject));
		// new scenario...
		csrCertFile = new File(pemDir, "csr-cert.pem");
		pemObject = PemObjectReader.getPemObject(csrCertFile);
		actual = pemObject.getType();
		expected = PemType.CERTIFICATE_REQUEST_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.CERTIFICATE_REQUEST, PemObjectReader.getPemType(pemObject));
		// new scenario...
		newCsrCertFile = new File(pemDir, "new-csr-cert.pem");
		pemObject = PemObjectReader.getPemObject(newCsrCertFile);
		actual = pemObject.getType();
		expected = PemType.NEW_CERTIFICATE_REQUEST_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.NEW_CERTIFICATE_REQUEST, PemObjectReader.getPemType(pemObject));
		// new scenario...
		pkcs7File = new File(pemDir, "pkcs7.pem");
		pemObject = PemObjectReader.getPemObject(pkcs7File);
		actual = pemObject.getType();
		expected = PemType.PKCS7_KEY_NAME;
		assertEquals(expected, actual);
		assertEquals(PemType.PKCS7_KEY, PemObjectReader.getPemType(pemObject));
	}

	/**
	 * Test method for {@link PemObjectReader#getPemObject(String)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetPemObjectWithPemString() throws IOException
	{
		String actual;
		String expected;
		String privateKeyBase64Encoded = PrivateKeyExtensionsTest.PRIVATE_KEY_BASE64_ENCODED;
		pemObject = PemObjectReader.getPemObject(privateKeyBase64Encoded);
		assertNotNull(pemObject);
		actual = pemObject.getType();
		expected = PemType.RSA_PRIVATE_KEY_NAME;
		assertEquals(expected, actual);
		actual = PemObjectReader.toPemFormat(pemObject);
		assertNotNull(actual);
		expected = privateKeyBase64Encoded;
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
		Optional<PrivateKey> actual;
		// new scenario...
		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privatekeyPemFile = new File(privatekeyPemDir, "id_rsa");

		actual = PemObjectReader.readPemPrivateKey(privatekeyPemFile, "secret");
		assertTrue(actual.isPresent());
		// new scenario...
		privatekeyPemFile = new File(privatekeyPemDir, "test.key");

		actual = PemObjectReader.readPemPrivateKey(privatekeyPemFile, "bosco");
		assertTrue(actual.isPresent());
	}

	/**
	 * Test method for {@link PemObjectReader#readPemPrivateKey(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testReadPemPrivateKeyWithoutPassword() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		File privatekeyPemDir;
		File privatekeyPemFile;
		PrivateKey privateKey;
		// new scenario...
		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		privateKey = PemObjectReader.readPemPrivateKey(privatekeyPemFile);
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
	 * Test method for {@link PemObjectReader#toPemFormat(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testToPemFormatFile() throws IOException
	{
		Optional<String> actual;
		File privatekeyPemDir;
		File privatekeyPemFile;

		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		actual = PemObjectReader.toPemFormat(privatekeyPemFile);
		System.out.println(actual);
		actual = PemObjectReader.toPemFormat(privateKeyDerFile);
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
