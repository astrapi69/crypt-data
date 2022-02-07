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
package io.github.astrapi69.crypto.factory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * The factory class {@link KeyStoreFactory} holds methods for creating {@link KeyStore} objects.
 */
public final class KeyStoreFactory
{

	private KeyStoreFactory()
	{
	}

	/**
	 * Factory method for create a new {@link KeyStore} object loaded from an existing
	 * {@link KeyStore} object from the given file.
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @return the loaded {@link KeyStore} object
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static KeyStore loadKeyStore(final File keystoreFile, final String type,
		final String password)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		final KeyStore keyStore = KeyStore.getInstance(type);
		keyStore.load(new FileInputStream(keystoreFile), password.toCharArray());
		return keyStore;
	}

	/**
	 * Factory method for create a new empty {@link KeyStore} object and save it to the given file
	 * with the given parameters.
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @return the loaded {@link KeyStore} object
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static KeyStore newKeyStore(final File keystoreFile, final String type,
		final String password)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		final KeyStore keyStore = KeyStore.getInstance(type);
		// initialize keystore
		keyStore.load(null, password.toCharArray());
		// get output stream
		OutputStream out = new FileOutputStream(keystoreFile);
		// store to new file
		keyStore.store(out, password.toCharArray());
		return keyStore;
	}

	/**
	 * Factory method for load the {@link KeyStore} object from the given already existing file
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param keystoreFile
	 *            the already existing keystore file
	 * @return the loaded {@link KeyStore} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @deprecated use instead the method <code>loadKeyStore</code> Note: will be removed in the
	 *             next minor version
	 */
	@Deprecated
	public static KeyStore newKeyStore(final String type, final String password,
		final File keystoreFile)
		throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException
	{
		return newKeyStore(type, password, keystoreFile, false);
	}

	/**
	 * Factory method for create a new empty {@link KeyStore} object and save it to the given file
	 * with the given parameters or load an existing {@link KeyStore} object from the given file.
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @param createNewKeyStore
	 *            if the {@linkplain KeyStore} should be new created.
	 * @return the loaded {@link KeyStore} object
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static KeyStore newKeyStore(final String type, final String password,
		final File keystoreFile, final boolean createNewKeyStore)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		return createNewKeyStore
			? newKeyStore(keystoreFile, type, password)
			: loadKeyStore(keystoreFile, type, password);
	}

}
