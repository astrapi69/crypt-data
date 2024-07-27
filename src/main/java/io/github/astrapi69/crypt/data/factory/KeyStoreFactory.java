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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.key.KeyStoreExtensions;
import io.github.astrapi69.crypt.data.model.KeyInfo;
import io.github.astrapi69.crypt.data.model.KeyStoreInfo;
import io.github.astrapi69.file.create.FileInfo;

/**
 * The factory class {@link KeyStoreFactory} holds methods for creating {@link KeyStore} objects
 */
public final class KeyStoreFactory
{

	private KeyStoreFactory()
	{
	}

	/**
	 * Factory method for creating a new {@link KeyStore} object loaded from an existing
	 * {@link KeyStore} object from the given file
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @return the loaded {@link KeyStore} object
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static KeyStore loadKeyStore(final File keystoreFile, final String type,
		final String password)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		return loadKeyStore(keystoreFile, type, password.toCharArray());
	}

	/**
	 * Factory method for creating a new {@link KeyStore} object from the given {@link KeyStoreInfo}
	 * object loaded from an existing {@link KeyStore} object
	 *
	 * @param keyStoreInfo
	 *            the {@link KeyStoreInfo} object
	 * @return the new {@link KeyStore} object
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws FileNotFoundException
	 *             if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static KeyStore loadKeyStore(final KeyStoreInfo keyStoreInfo)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		return loadKeyStore(FileInfo.toFile(keyStoreInfo.getFileInfo()), keyStoreInfo.getType(),
			keyStoreInfo.getKeystorePassword());
	}

	/**
	 * Factory method for creating a new {@link KeyStore} object loaded from an existing
	 * {@link KeyStore} object from the given file
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @return the loaded {@link KeyStore} object
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static KeyStore loadKeyStore(final File keystoreFile, final String type,
		final char[] password)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		final KeyStore keyStore = KeyStore.getInstance(type);
		keyStore.load(new FileInputStream(keystoreFile), password);
		return keyStore;
	}

	/**
	 * Factory method for creating a new empty {@link KeyStore} object and saving it to the given
	 * file with the given parameters
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @return the loaded {@link KeyStore} object
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws FileNotFoundException
	 *             if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static KeyStore newKeyStore(final File keystoreFile, final String type,
		final String password)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		return newKeyStore(keystoreFile, type, password.toCharArray());
	}

	/**
	 * Factory method for creating a new empty {@link KeyStore} object and saving it to the given
	 * file with the given parameters
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore as char array
	 * @return the loaded {@link KeyStore} object
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws FileNotFoundException
	 *             if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static KeyStore newKeyStore(final File keystoreFile, final String type,
		final char[] password)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		final KeyStore keyStore = KeyStore.getInstance(type);
		// initialize keystore
		keyStore.load(null, password);
		// get output stream
		OutputStream out = new FileOutputStream(keystoreFile);
		// store to new file
		keyStore.store(out, password);
		return keyStore;
	}

	/**
	 * Factory method for creating a new empty {@link KeyStore} object and saving it to the given
	 * file with the given parameters or loading an existing {@link KeyStore} object from the given
	 * file
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @param createNewKeyStore
	 *            if the {@linkplain KeyStore} should be newly created
	 * @return the loaded {@link KeyStore} object
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws FileNotFoundException
	 *             if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @deprecated use instead the method <code>loadKeyStore</code> or <code>loadKeyStore</code>
	 *             <br>
	 *             Note: will be removed in the next minor version
	 */
	@Deprecated
	public static KeyStore newKeyStore(final String type, final String password,
		final File keystoreFile, final boolean createNewKeyStore)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		return createNewKeyStore
			? newKeyStore(keystoreFile, type, password)
			: loadKeyStore(keystoreFile, type, password);
	}

	/**
	 * Factory method for creating a new empty {@link KeyStore} object from the given
	 * {@link KeyStoreInfo} object
	 *
	 * @param keyStoreInfo
	 *            the {@link KeyStoreInfo} object
	 * @return the new {@link KeyStore} object
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws FileNotFoundException
	 *             if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static KeyStore newKeyStore(final KeyStoreInfo keyStoreInfo)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		return newKeyStore(FileInfo.toFile(keyStoreInfo.getFileInfo()), keyStoreInfo.getType(),
			keyStoreInfo.getKeystorePassword());
	}

	/**
	 * Creates a new keystore for SSL, saves the provided private key and certificate in it, and
	 * stores it in a file
	 *
	 * @param keyStoreInfo
	 *            the information about the keystore, including file info and keystore password
	 * @param privateKeyModel
	 *            the model containing the private key information
	 * @param certificateModel
	 *            the model containing the certificate information
	 * @param certificateAlias
	 *            the alias under which the certificate and key will be stored
	 * @param keyPassword
	 *            the password for protecting the key
	 * @return the new {@link KeyStore} object
	 * @throws CertificateException
	 *             if an error occurs while handling the certificate
	 * @throws KeyStoreException
	 *             if an error occurs while handling the keystore
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm for recovering the key cannot be found
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static KeyStore newKeystoreAndSaveForSsl(KeyStoreInfo keyStoreInfo,
		KeyInfo privateKeyModel, KeyInfo certificateModel, String certificateAlias,
		char[] keyPassword)
		throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		// Convert KeyModel to actual Key and Certificate objects
		PrivateKey privateKey = KeyInfoExtensions.toPrivateKey(privateKeyModel);
		X509Certificate certificate = KeyInfoExtensions.toX509Certificate(certificateModel);
		return newKeystoreAndSaveForSsl(keyStoreInfo, privateKey, certificate, certificateAlias,
			keyPassword);
	}

	/**
	 * Creates a new keystore for SSL, saves the provided private key and certificate in it, and
	 * stores it in a file
	 *
	 * @param keyStoreInfo
	 *            the information about the keystore, including file info and keystore password
	 * @param privateKey
	 *            the private key
	 * @param certificate
	 *            the certificate
	 * @param certificateAlias
	 *            the alias under which the certificate and key will be stored
	 * @param keyPassword
	 *            the password for protecting the key
	 * @return the new {@link KeyStore} object
	 * @throws CertificateException
	 *             if an error occurs while handling the certificate
	 * @throws KeyStoreException
	 *             if an error occurs while handling the keystore
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm for recovering the key cannot be found
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static KeyStore newKeystoreAndSaveForSsl(KeyStoreInfo keyStoreInfo,
		PrivateKey privateKey, Certificate certificate, String certificateAlias, char[] keyPassword)
		throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		// Initialize a KeyStore and store the key pair and certificate
		KeyStore keyStore = KeyStoreInfo.toKeyStore(keyStoreInfo);

		keyStore.setKeyEntry(certificateAlias, privateKey, keyPassword,
			new java.security.cert.Certificate[] { certificate });
		File keystoreFile = FileInfo.toFile(keyStoreInfo.getFileInfo());
		KeyStoreExtensions.store(keyStore, keystoreFile, keyPassword);
		return keyStore;
	}
}
