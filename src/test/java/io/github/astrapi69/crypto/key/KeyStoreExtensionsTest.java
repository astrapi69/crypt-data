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
package io.github.astrapi69.crypto.key;

import static org.testng.Assert.assertNotNull;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.search.PathFinder;
import io.github.astrapi69.crypto.algorithm.KeystoreType;
import io.github.astrapi69.crypto.factories.KeyStoreFactory;
import io.github.astrapi69.crypto.key.reader.CertificateReader;

/**
 * The unit test class for the class {@link KeyStoreExtensions}
 */
public class KeyStoreExtensionsTest
{

	String alias = "alias-for-delete";
	/** The certificate for tests. */
	X509Certificate certificate;
	String newAlias = "new-alias";
	String password = "foobar-secret-pw";

	File privatekeyDerFile;
	File publickeyDerDir;

	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		if (certificate == null)
		{
			final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
			final File certificatePemFile = new File(pemDir, "certificate.pem");
			certificate = CertificateReader.readPemCertificate(certificatePemFile);
			assertNotNull(certificate);

		}

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(publickeyDerDir, "keystore.jks");
		KeyStore keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password,
			privatekeyDerFile, true);
		assertNotNull(keyStore);
		assertFalse(keyStore.containsAlias(alias));
		keyStore.setCertificateEntry(alias, certificate);

		assertTrue(keyStore.containsAlias(alias));
		keyStore.store(new FileOutputStream(privatekeyDerFile), password.toCharArray());
	}

	/**
	 * Tear down method will be invoked after every unit test method
	 */
	@AfterMethod
	protected void tearDown()
	{
		privatekeyDerFile.delete();
	}

	/**
	 * Test method for {@link KeyStoreExtensions#deleteAlias(File, String, String)}
	 */
	@Test
	public void testDeleteAlias() throws Exception
	{
		KeyStore keyStore;
		boolean containsAlias;

		KeyStoreExtensions.deleteAlias(privatekeyDerFile, alias, password);

		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, privatekeyDerFile,
			true);
		containsAlias = keyStore.containsAlias(alias);

		assertFalse(containsAlias);
	}

	/**
	 * Test method for {@link KeyStoreExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyStoreExtensions.class);
	}

}
