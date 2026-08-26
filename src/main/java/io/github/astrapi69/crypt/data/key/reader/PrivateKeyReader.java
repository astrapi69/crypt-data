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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyStringEntry;
import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.api.provider.SecurityProvider;
import io.github.astrapi69.crypt.data.algorithm.CryptoAlgorithm;
import io.github.astrapi69.crypt.data.model.KeyInfo;
import lombok.extern.java.Log;

/**
 * The class {@link PrivateKeyReader} is a utility class for reading private keys in *.der or *.pem
 * format
 */
@Log
public final class PrivateKeyReader
{

	/**
	 * The five dashes and the word that open every pem document, whatever it holds
	 */
	private static final String PEM_HEADER_START = "-----BEGIN";

	private PrivateKeyReader()
	{
	}

	/**
	 * Checks if the given {@link File} is in pem format
	 *
	 * @param file
	 *            the file
	 * @return true, if the given {@link File} is in pem format otherwise false
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static boolean isPemFormat(final File file) throws IOException
	{
		return PemObjectReader.isPemObject(file);
	}

	/**
	 * Resolves the format of the given {@link File}
	 *
	 * @param file
	 *            the file
	 * @return true, if the given {@link File} is in pem format otherwise false
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static KeyFileFormat getKeyFormat(final File file) throws IOException
	{
		if (!validatePrivateKey(file))
		{
			return KeyFileFormat.UNKNOWN;
		}
		if (isPemFormat(file))
		{
			return KeyFileFormat.PEM;
		}
		return KeyFileFormat.DER;
	}

	/**
	 * Checks if the given {@link File} is password protected
	 *
	 * @param file
	 *            the file that contains the private key
	 * @return true, if the given {@link File} is password protected otherwise false
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static boolean isPrivateKeyPasswordProtected(final File file) throws IOException
	{
		// a private key file that cannot be read without a password is exactly a file that does
		// not validate as a plain private key, so this is the negation of validatePrivateKey
		return !validatePrivateKey(file);
	}

	/**
	 * Checks if the given {@link File} is a valid private key file
	 *
	 * @param file
	 *            the file to check
	 * @return true, if the given {@link File} is a valid private key file otherwise false
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static boolean validatePrivateKey(final File file) throws IOException
	{
		boolean valid = true;
		if (isPemFormat(file))
		{
			try
			{
				readPemPrivateKey(file);
			}
			catch (Exception e)
			{
				valid = false;
			}
		}
		else
		{
			try
			{
				valid = readPrivateKey(file) != null;
			}
			catch (Exception e)
			{
				valid = false;
			}
		}
		return valid;
	}

	/**
	 * Read the private key from a pem file as base64 encoded {@link String} value
	 *
	 * @param file
	 *            the file( in *.pem format) that contains the private key
	 * @return the base64 encoded {@link String} value
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static String readPemFileAsBase64(final File file) throws IOException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		final String privateKeyPem = new String(keyBytes);
		String privateKeyAsBase64String = null;
		if (privateKeyPem.contains(KeyStringEntry.BEGIN_PRIVATE_KEY_PREFIX.getValue()))
		{
			// PKCS#8 format
			privateKeyAsBase64String = new String(keyBytes)
				.replace(KeyStringEntry.BEGIN_PRIVATE_KEY_PREFIX.getValue(), "")
				.replaceAll(System.lineSeparator(), "")
				.replace(KeyStringEntry.END_PRIVATE_KEY_SUFFIX.getValue(), "").trim();
		}
		if (privateKeyPem.contains(KeyStringEntry.BEGIN_RSA_PRIVATE_KEY_PREFIX.getValue()))
		{
			// PKCS#1 format
			privateKeyAsBase64String = new String(keyBytes)
				.replace(KeyStringEntry.BEGIN_RSA_PRIVATE_KEY_PREFIX.getValue(), "")
				.replaceAll(System.lineSeparator(), "")
				.replace(KeyStringEntry.END_RSA_PRIVATE_KEY_SUFFIX.getValue(), "").trim();
		}
		return privateKeyAsBase64String;
	}

	/**
	 * Reads the given {@link File}( in *.pem format) with the default RSA algorithm and returns the
	 * {@link PrivateKey} object
	 *
	 * @param file
	 *            the file( in *.pem format) that contains the private key
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static PrivateKey readPemPrivateKey(final File file) throws IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return PemObjectReader.readPemPrivateKey(file);
	}

	/**
	 * Reads the given {@link File}( in *.pem format) with given algorithm and returns the
	 * {@link PrivateKey} object
	 *
	 * @param file
	 *            the file( in *.pem format) that contains the private key
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static PrivateKey readPemPrivateKey(final File file, final String algorithm)
		throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException
	{
		return PemObjectReader.readPrivateKey(file, CryptoAlgorithm.newAlgorithm(algorithm));
	}

	/**
	 * Reads the given {@link String}( in *.pem format) with given algorithm and returns the
	 * {@link PrivateKey} object
	 *
	 * @param privateKeyAsString
	 *            the private key as string( in *.pem format)
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static PrivateKey readPemPrivateKey(final String privateKeyAsString,
		final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final byte[] decoded = new Base64().decode(privateKeyAsString);
		return readPrivateKey(decoded, algorithm);
	}

	/**
	 * Reads the given {@link PemObject} with given algorithm and returns the {@link PrivateKey}
	 * object
	 *
	 * @param pemObject
	 *            the pem object
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static PrivateKey readPrivateKey(final PemObject pemObject, final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final byte[] decoded = pemObject.getContent();
		return readPrivateKey(decoded, algorithm);
	}

	/**
	 * Reads the given {@link String} and returns the {@link PrivateKey} object it holds, of
	 * whatever algorithm it was made with
	 * <p>
	 * Two shapes are read. A whole pem document, headers included, is taken as one: the header
	 * names the algorithm of a traditional key and the algorithm identifier names it for a PKCS#8
	 * one. A bare base64 body without headers is read as PKCS#8, which names its own algorithm, and
	 * failing that as the traditional RSA body that {@link #readPemFileAsBase64(File)} produces -
	 * the only headerless shape that can be read at all, because nothing else in it says what it
	 * is.
	 * <p>
	 * The algorithm used to be taken as RSA and a whole pem document was refused, although the
	 * parameter has always been documented as being in pem format (issue #19).
	 *
	 * @param privateKeyAsString
	 *            the private key as a whole pem document or as a bare base64 body
	 * @return the {@link PrivateKey} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if the given text holds no private key that can be read
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static PrivateKey readPemPrivateKey(final String privateKeyAsString)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		Objects.requireNonNull(privateKeyAsString);
		if (privateKeyAsString.contains(PEM_HEADER_START))
		{
			try
			{
				return PemObjectReader.readPemPrivateKey(privateKeyAsString);
			}
			catch (IOException cannotBeParsed)
			{
				throw new InvalidKeySpecException(
					"The given pem text could not be parsed: " + cannotBeParsed.getMessage(),
					cannotBeParsed);
			}
		}
		final byte[] decoded = new Base64().decode(privateKeyAsString);
		PrivateKey pkcs8Key = asPkcs8Key(decoded);
		if (pkcs8Key != null)
		{
			return pkcs8Key;
		}
		// a body stripped of its header names nothing, and a traditional rsa key is the only shape
		// this method has ever been able to read without one
		try
		{
			return readPrivateKey(decoded, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		}
		catch (InvalidKeySpecException noTraditionalRsaKeyEither)
		{
			throw new InvalidKeySpecException(
				"The given text has no pem header, so nothing names its algorithm, and its base64 "
					+ "is no PKCS#8 structure either. Only a traditional RSA body can be read "
					+ "without a header, and this is not one",
				noTraditionalRsaKeyEither);
		}
	}

	/**
	 * Reads the given byte array as a PKCS#8 structure, which is the encoding that names the
	 * algorithm of the key it wraps, and returns the {@link PrivateKey} object it holds
	 *
	 * @param privateKeyBytes
	 *            the byte array to read
	 * @return the {@link PrivateKey} object or null if the given bytes are no PKCS#8 key
	 */
	private static PrivateKey asPkcs8Key(final byte[] privateKeyBytes)
	{
		try
		{
			return new JcaPEMKeyConverter().setProvider(SecurityProvider.BC.name())
				.getPrivateKey(PrivateKeyInfo.getInstance(privateKeyBytes));
		}
		catch (IllegalArgumentException | IOException noPkcs8KeyHere)
		{
			// whether the bytes are no PKCS#8 structure at all or name an algorithm no key can be
			// built for, the answer to the caller is the same one: this is not it, try the other
			// shape. What is thrown when neither shape works is built there, with both attempts
			// named
			return null;
		}
	}

	/**
	 * Reads the given byte array with the default RSA algorithm and returns the {@link PrivateKey}
	 * object
	 *
	 * @param privateKeyBytes
	 *            the byte array that contains the private key bytes
	 * @return the {@link PrivateKey} object
	 */
	public static PrivateKey readPrivateKey(final byte[] privateKeyBytes)
	{
		return getPrivateKey(privateKeyBytes).orElse(null);
	}

	/**
	 * Reads the given byte array with the given algorithm and returns the {@link PrivateKey} object
	 *
	 * @param privateKeyBytes
	 *            the byte array that contains the private key bytes
	 * @param algorithm
	 *            the algorithm for the {@link KeyFactory}
	 * @return the {@link PrivateKey} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 */
	public static PrivateKey readPrivateKey(final byte[] privateKeyBytes, final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePrivate(keySpec);
	}

	/**
	 * Reads the given {@link KeyInfo} object and returns the {@link PrivateKey} object
	 *
	 * @param keyInfo
	 *            the info model for create the private key
	 * @return the {@link PrivateKey} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 */
	public static PrivateKey readPrivateKey(KeyInfo keyInfo)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		Objects.requireNonNull(keyInfo);
		KeyType keyType = KeyType.toKeyType(keyInfo.getKeyType());
		if (!keyType.equals(KeyType.PRIVATE_KEY))
		{
			throw new RuntimeException("Given KeyModel:" + keyInfo + "\n is not a private key");
		}
		return readPrivateKey(keyInfo.getEncoded(), keyInfo.getAlgorithm());
	}

	/**
	 * Reads the given {@link File} with the default RSA algorithm and returns the
	 * {@link PrivateKey} object
	 *
	 * @param file
	 *            the file that contains the private key
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static PrivateKey readPrivateKey(final File file) throws IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		if (isPemFormat(file))
		{
			return readPemPrivateKey(file);
		}
		return getPrivateKey(file).orElse(null);
	}

	/**
	 * Gets an {@link Optional} with the private key from the given file. If it does not match, the
	 * optional is empty
	 *
	 * @param privateKeyFile
	 *            the file that contains the private key
	 * @return the {@link Optional} object with the private key from the given file or an empty
	 *         {@link Optional} object if it does not match
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static Optional<PrivateKey> getPrivateKey(File privateKeyFile) throws IOException
	{
		return getPrivateKey(Files.readAllBytes(privateKeyFile.toPath()));
	}

	/**
	 * Gets an {@link Optional} with the private key from the given file. If it does not match, the
	 * optional is empty
	 *
	 * @param privateKeyBytes
	 *            the byte array that contains the private key bytes
	 * @return the {@link Optional} object with the private key from the given file or an empty
	 *         {@link Optional} object if it does not match
	 */
	public static Optional<PrivateKey> getPrivateKey(final byte[] privateKeyBytes)
	{
		try
		{
			return Optional.of(PrivateKeyReader.readPrivateKey(privateKeyBytes,
				KeyPairGeneratorAlgorithm.DIFFIE_HELLMAN.getAlgorithm()));
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e)
		{
			log.log(Level.WARNING,
				"Given private key file is not stored in 'DiffieHellman' algorithm", e);
		}
		try
		{
			return Optional.of(PrivateKeyReader.readPrivateKey(privateKeyBytes,
				KeyPairGeneratorAlgorithm.DSA.getAlgorithm()));
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e)
		{
			log.log(Level.WARNING, "Given private key file is not stored in 'DSA' algorithm", e);
		}
		try
		{
			return Optional.of(PrivateKeyReader.readPrivateKey(privateKeyBytes,
				KeyPairGeneratorAlgorithm.EC.getAlgorithm()));
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e)
		{
			log.log(Level.WARNING, "Given private key file is not stored in 'EC' algorithm", e);
		}
		try
		{
			return Optional.of(PrivateKeyReader.readPrivateKey(privateKeyBytes,
				KeyPairGeneratorAlgorithm.RSASSA_PSS.getAlgorithm()));
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e)
		{
			log.log(Level.WARNING, "Given private key file is not stored in 'RSASSA-PSS' algorithm",
				e);
		}
		try
		{
			return Optional.of(PrivateKeyReader.readPrivateKey(privateKeyBytes,
				KeyPairGeneratorAlgorithm.RSA.getAlgorithm()));
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e)
		{
			log.log(Level.WARNING, "Given private key file is not stored in 'RSA' algorithm", e);
		}
		// every candidate algorithm failed: the bytes are not a private key this reader can parse
		return Optional.empty();
	}

	/**
	 * Reads the given {@link File}( in *.der format) with the given algorithm and returns the
	 * {@link PrivateKey} object
	 *
	 * @param file
	 *            the file( in *.der format) that contains the private key
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 */
	public static PrivateKey readPrivateKey(final File file, final String algorithm)
		throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		return readPrivateKey(keyBytes, algorithm);
	}

	/**
	 * Constructs from the given root, parent directory, and file name the file and reads the
	 * private key
	 *
	 * @param root
	 *            the root directory of the parent directory
	 * @param directory
	 *            the parent directory of the private key file
	 * @param fileName
	 *            the file name of the file that contains the private key
	 * @return the private key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             the no such provider exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static PrivateKey readPrivateKey(final File root, final String directory,
		final String fileName) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		return PrivateKeyReader.readPrivateKey(new File(new File(root, directory), fileName));
	}
}
