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
package io.github.astrapi69.crypt.data.model;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.file.create.FileInfo;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

/**
 * Data class representing key store information.
 */
@Data
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class KeyStoreInfo
{

	/**
	 * The file information of the key store.
	 */
	@NonNull
	private FileInfo fileInfo;

	/**
	 * The type of the key store.
	 */
	@NonNull
	private String type;

	/**
	 * The password for the key store.
	 */
	@NonNull
	private char[] keystorePassword;

	/**
	 * Factory method to create a new empty {@link KeyStore} object from the given
	 * {@link KeyStoreInfo} object.
	 *
	 * @param keyStoreInfo
	 *            the {@link KeyStoreInfo} object containing the key store details.
	 * @return the newly created {@link KeyStore} object.
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store.
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails.
	 * @throws CertificateException
	 *             if there is an error with a certificate.
	 * @throws FileNotFoundException
	 *             if the key store file is not found.
	 * @throws IOException
	 *             if an I/O exception occurs.
	 */
	public static KeyStore toKeyStore(KeyStoreInfo keyStoreInfo)
		throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		return KeyStoreFactory.newKeyStore(keyStoreInfo);
	}
}
