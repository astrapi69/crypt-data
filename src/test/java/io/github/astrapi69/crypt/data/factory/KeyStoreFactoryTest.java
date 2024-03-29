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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.type.KeystoreType;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyStoreFactory}
 */
public class KeyStoreFactoryTest
{
	/**
	 * Test method for {@link KeyStoreFactory#newKeyStore(String, String, File, boolean)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm used to check the integrity of the keystore cannot be found
	 * @throws CertificateException
	 *             if any of the certificates in the keystore could not be loaded
	 * @throws FileNotFoundException
	 *             if the file not found
	 * @throws KeyStoreException
	 *             if the keystore has not been initialized (loaded).
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testNewKeyStore() throws NoSuchAlgorithmException, CertificateException,
		FileNotFoundException, KeyStoreException, IOException
	{
		File publickeyDerDir;
		File keystoreJksFile;
		KeyStore keystore;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		keystoreJksFile = new File(publickeyDerDir, "keystore.jks");

		keystore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), "foobar-secret-pw",
			keystoreJksFile, true);
		assertNotNull(keystore);

		keystore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), "foobar-secret-pw",
			keystoreJksFile, false);
		assertNotNull(keystore);

		keystore = KeyStoreFactory.loadKeyStore(keystoreJksFile, KeystoreType.JKS.name(),
			"foobar-secret-pw");
		assertNotNull(keystore);
		FileUtils.deleteQuietly(keystoreJksFile);
	}

	/**
	 * Test method for {@link KeyStoreFactory#loadKeyStore(File, String, String)}
	 *
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testLoadKeyStore()
		throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		File jksDir;
		File keystoreJksFile;
		KeyStore keystore;

		jksDir = new File(PathFinder.getSrcTestResourcesDir(), "jks");
		keystoreJksFile = new File(jksDir, "keystore.jks");

		keystore = KeyStoreFactory.loadKeyStore(keystoreJksFile, KeystoreType.JKS.name(),
			"keystore-pw");
		assertNotNull(keystore);
	}

	/**
	 * Test method for {@link KeyStoreFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyStoreFactory.class);
	}

}
