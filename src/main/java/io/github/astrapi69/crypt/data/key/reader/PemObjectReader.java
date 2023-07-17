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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.api.provider.SecurityProvider;
import lombok.NonNull;

/**
 * The class {@link PemObjectReader} is a utility class for reading {@link PemObject} from a file.
 */
public final class PemObjectReader
{

	private PemObjectReader()
	{
	}

	/**
	 * Gets the pem object.
	 *
	 * @param file
	 *            the file
	 * @return the pem object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PemObject getPemObject(final @NonNull File file) throws IOException
	{
		PemObject pemObject;
		try (PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(file))))
		{
			pemObject = pemReader.readPemObject();
		}
		return pemObject;
	}

	/**
	 * Gets the pem object from the given pem string
	 *
	 * @param pemString
	 *            the pem as string
	 * @return the pem object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PemObject getPemObject(final @NonNull String pemString) throws IOException
	{
		PemObject pemObject;
		try (PemReader pemReader = new PemReader(
			new InputStreamReader(new ByteArrayInputStream(pemString.getBytes()))))
		{
			pemObject = pemReader.readPemObject();
		}
		return pemObject;
	}

	/**
	 * Checks if the given File contains a pem object
	 *
	 * @param file
	 *            the file
	 * @return true if the file contains a pem object otherwise false
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static boolean isPemObject(final @NonNull File file) throws IOException
	{
		return getPemObject(file) != null;
	}

	/**
	 * Reads the given {@link File}( in *.pem format) that contains a key in pem format
	 *
	 * @param keyFile
	 *            the key in pem format
	 * @return the key object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static Object readPemKeyObject(final @NonNull File keyFile) throws IOException
	{
		try (PEMParser pemParser = new PEMParser(
			new InputStreamReader(new FileInputStream(keyFile))))
		{
			return pemParser.readObject();
		}
	}

	/**
	 * Reads the given {@link File}( in *.pem format) that contains a password protected private
	 * key.
	 *
	 * @param keyFile
	 *            the file with the password protected private key
	 * @param password
	 *            the password
	 * @return the {@link PrivateKey} object or null if the given file is not a password protected
	 *         private key.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static Optional<PrivateKey> readPemPrivateKey(final @NonNull File keyFile,
		String password) throws IOException
	{
		Object pemKeyObject = readPemKeyObject(keyFile);
		if (pemKeyObject instanceof PEMEncryptedKeyPair)
		{
			PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair)pemKeyObject;
			PEMDecryptorProvider pemDecryptorProvider = new JcePEMDecryptorProviderBuilder()
				.build(password.toCharArray());
			PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(pemDecryptorProvider);

			JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
				.setProvider(SecurityProvider.BC.name());
			return Optional.of(converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo()));
		}
		return Optional.empty();
	}

	/**
	 * Reads the given {@link File}( in *.pem format) that contains private key.
	 *
	 * @param keyPemFile
	 *            the file with the private key ( in *.pem format)
	 * @return the {@link PrivateKey} object or null if the given file is not private key
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPemPrivateKey(final @NonNull File keyPemFile) throws IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return readPrivateKey(keyPemFile, KeyPairGeneratorAlgorithm.RSA);
	}

	/**
	 * Reads the given {@link File}( in *.pem format) that contains private key.
	 *
	 * @param keyPemFile
	 *            the file with the private key ( in *.pem format)
	 * @param algorithm
	 *            the algorithm for the {@link KeyFactory}
	 * @return the {@link PrivateKey} object or null if the given file is not private key
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPrivateKey(final @NonNull File keyPemFile,
		final @NonNull Algorithm algorithm) throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		return PrivateKeyReader.readPrivateKey(getPemObject(keyPemFile).getContent(),
			algorithm.getAlgorithm());
	}

	/**
	 * Transform the given {@link PemObject} object in pem format {@link String} object.
	 *
	 * @param pemObject
	 *            the pem object
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String toPemFormat(final @NonNull PemObject pemObject) throws IOException
	{
		final StringWriter stringWriter = new StringWriter();
		final PemWriter pemWriter = new PemWriter(stringWriter);
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		return stringWriter.toString();
	}

	/**
	 * Transform the given key {@link File} object in pem format {@link String} object
	 *
	 * @param file
	 *            the key file
	 * @return the string or null if the given key file is not in pem format
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static Optional<String> toPemFormat(final @NonNull File file) throws IOException
	{
		PemObject pemObject = getPemObject(file);
		if (pemObject != null)
		{
			return Optional.of(toPemFormat(pemObject));
		}
		return Optional.empty();
	}

	/**
	 * Transform the given {@link PemObject} object in to a byte array in the der format.
	 *
	 * @param pemObject
	 *            the pem object
	 * @return the byte array in the der format
	 */
	public static byte[] toDer(final @NonNull PemObject pemObject)
	{
		return pemObject.getContent();
	}

	/**
	 * Get the {@link PemType} the given {@link PemObject} object
	 *
	 * @param pemObject
	 *            the pem object
	 * @return the {@link PemType} the given {@link PemObject} object
	 */
	public static PemType getPemType(final @NonNull PemObject pemObject)
	{
		return PemType.toPemType(pemObject.getType());
	}

	/**
	 * Get the {@link PemType} the given {@link File} object
	 *
	 * @param file
	 *            the file
	 * @return the {@link PemType} the given {@link File} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PemType getPemType(final @NonNull File file) throws IOException
	{
		PemObject pemObject = getPemObject(file);
		if (pemObject == null)
		{
			throw new RuntimeException("Given file contains no pem formatted key");
		}
		return getPemType(pemObject);
	}

}
