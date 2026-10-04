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
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Optional;
import java.util.logging.Level;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import io.github.astrapi69.crypt.api.provider.SecurityProvider;
import io.github.astrapi69.crypt.data.factory.CipherFactory;
import io.github.astrapi69.crypt.data.factory.KeySpecFactory;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import lombok.extern.java.Log;

/**
 * The class {@link EncryptedPrivateKeyReader} is a utility class for reading encrypted private keys
 * that are protected with a password
 */
@Log
public final class EncryptedPrivateKeyReader
{

	private EncryptedPrivateKeyReader()
	{
	}

	/**
	 * Reads from the given {@link File} that contains the password protected {@link KeyPair} and
	 * returns it
	 *
	 * @param encryptedPrivateKeyFile
	 *            the file that contains the password protected {@link KeyPair}
	 * @param password
	 *            the password
	 * @return the key pair
	 * @throws FileNotFoundException
	 *             is thrown if the file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws PEMException
	 *             is thrown if an error occurs on read the pem file
	 * @throws PKCSException
	 *             is thrown if an error occurs on read the key file
	 */
	public static KeyPair getKeyPair(final File encryptedPrivateKeyFile, final String password)
		throws FileNotFoundException, IOException, PEMException, PKCSException
	{
		Object pemObject;
		try (PEMParser pemParser = new PEMParser(new FileReader(encryptedPrivateKeyFile)))
		{
			pemObject = pemParser.readObject();
		}

		JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter()
			.setProvider(SecurityProvider.BC.name());
		KeyPair keyPair;
		if (pemObject instanceof PEMEncryptedKeyPair)
		{
			PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder()
				.setProvider(SecurityProvider.BC.name()).build(password.toCharArray());
			keyPair = keyConverter
				.getKeyPair(((PEMEncryptedKeyPair)pemObject).decryptKeyPair(decryptorProvider));
		}
		else if (pemObject instanceof PEMKeyPair)
		{
			keyPair = keyConverter.getKeyPair((PEMKeyPair)pemObject);
		}
		else if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo)
		{
			PKCS8EncryptedPrivateKeyInfo encryptedInfo = (PKCS8EncryptedPrivateKeyInfo)pemObject;
			PrivateKey privateKey = keyConverter.getPrivateKey(
				encryptedInfo.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder()
					.setProvider(SecurityProvider.BC.name()).build(password.toCharArray())));
			keyPair = new KeyPair(null, privateKey); // No public key available in this case
		}
		else if (pemObject == null)
		{
			throw new PEMException(
				"No PEM object found in file: " + encryptedPrivateKeyFile.getAbsolutePath());
		}
		else
		{
			throw new PEMException("Invalid PEM object type: " + pemObject.getClass().getName());
		}
		return keyPair;
	}

	/**
	 * Reads the given byte array that contains a password protected private key
	 *
	 * @param encryptedPrivateKeyBytes
	 *            the password protected private key as the byte array
	 * @param password
	 *            the password
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails
	 */
	public static PrivateKey readPasswordProtectedPrivateKey(final byte[] encryptedPrivateKeyBytes,
		final String password, final String algorithm)
		throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
		InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		final KeySpec pkcs8KeySpec = decryptToPkcs8(encryptedPrivateKeyBytes, password);
		final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePrivate(pkcs8KeySpec);
	}

	/**
	 * Reads the given byte array with a password protected private key and returns the
	 * {@link PrivateKey} object, of whatever algorithm the key inside it was made with
	 *
	 * @param encryptedPrivateKeyBytes
	 *            the byte array with the password protected private key
	 * @param password
	 *            the password
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if the password is wrong or no key can be built from what was decrypted
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails
	 */
	public static PrivateKey readPasswordProtectedPrivateKey(final byte[] encryptedPrivateKeyBytes,
		final String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
		InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		final PKCS8EncodedKeySpec pkcs8KeySpec = decryptToPkcs8(encryptedPrivateKeyBytes, password);
		try
		{
			// what comes out of the decryption is a pkcs#8 structure, which names its own
			// algorithm. It used to be guessed at instead, from a list of four that left out the
			// edwards and montgomery families (issue #24)
			return new JcaPEMKeyConverter().setProvider(SecurityProvider.BC.name())
				.getPrivateKey(PrivateKeyInfo.getInstance(pkcs8KeySpec.getEncoded()));
		}
		catch (IllegalArgumentException | IOException noKeyInThere)
		{
			throw new InvalidKeySpecException(
				"What was decrypted is no private key structure: " + noKeyInThere.getMessage(),
				noKeyInThere);
		}
	}

	/**
	 * Decrypts the given password protected private key bytes and returns the PKCS#8 structure that
	 * was sealed in them
	 *
	 * @param encryptedPrivateKeyBytes
	 *            the byte array with the password protected private key
	 * @param password
	 *            the password
	 * @return the {@link PKCS8EncodedKeySpec} object that was decrypted
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if the password is wrong
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails
	 */
	private static PKCS8EncodedKeySpec decryptToPkcs8(final byte[] encryptedPrivateKeyBytes,
		final String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
		InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		final EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(
			encryptedPrivateKeyBytes);
		final String algName = encryptedPrivateKeyInfo.getAlgName();
		final Cipher cipher = CipherFactory.newCipher(algName);
		final KeySpec pbeKeySpec = KeySpecFactory.newPBEKeySpec(password);
		final SecretKeyFactory secretKeyFactory = SecretKeyFactoryExtensions
			.newSecretKeyFactory(algName);
		final Key pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);
		final AlgorithmParameters algParameters = encryptedPrivateKeyInfo.getAlgParameters();
		cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParameters);
		try
		{
			// the cipher is run here rather than through getKeySpec(Cipher), which checks the
			// decrypted bytes against what the jdk recognises as a key and refuses a
			// diffie-hellman key with "Cannot retrieve the PKCS8EncodedKeySpec". Whether the bytes
			// are a key is decided where the key is built, by whoever asked for it
			return new PKCS8EncodedKeySpec(
				cipher.doFinal(encryptedPrivateKeyInfo.getEncryptedData()));
		}
		catch (IllegalBlockSizeException | BadPaddingException wrongPassword)
		{
			throw new InvalidKeySpecException(
				"The password does not open this key: " + wrongPassword.getMessage(),
				wrongPassword);
		}
	}

	/**
	 * Reads the given {@link File} that contains a password protected private key, if fails null
	 * will be returned
	 *
	 * @param encryptedPrivateKeyFile
	 *            the file that contains the password protected private key
	 * @param password
	 *            the password
	 * @return the {@link PrivateKey} object or null if it fails
	 * @throws OperatorCreationException
	 *             is thrown if an error occurs on the operator creation
	 * @throws PKCSException
	 *             is thrown if an error occurs on read the key file
	 *
	 * @implNote The throws clause is wider than it was until 12.0.0, which declared only
	 *           {@code OperatorCreationException} and {@code PKCSException}. Widening it was a
	 *           source breaking change and it broke mystic-crypt-ui, whose two call sites handled
	 *           the old pair. It is not narrowed again: the caller adapted, with a single
	 *           {@code catch (IOException | GeneralSecurityException)}, and a catch for an
	 *           exception that is no longer declared does not compile - so taking the clause back
	 *           would break the same caller a second time, in the other direction. Narrow it only
	 *           together with every known caller, in one step, never on its own.
	 */
	public static PrivateKey readPasswordProtectedPrivateKey(final File encryptedPrivateKeyFile,
		final String password) throws OperatorCreationException, PKCSException, IOException,
		NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException,
		InvalidKeyException, InvalidAlgorithmParameterException
	{
		// this used to be getPrivateKey(...).orElse(null): a walk over rsa, diffie-hellman, dsa and
		// ec that left out the edwards and montgomery families, and turned running out of guesses
		// into a null - the same answer a wrong password and a file holding no key at all gave, so
		// the three could not be told apart (issue #24)
		if (PrivateKeyReader.isPemFormat(encryptedPrivateKeyFile))
		{
			return getKeyPair(encryptedPrivateKeyFile, password).getPrivate();
		}
		return readPasswordProtectedPrivateKey(Files.readAllBytes(encryptedPrivateKeyFile.toPath()),
			password);
	}

	/**
	 * Gets an {@link Optional} with the password protected private key from the given file. If it
	 * does not match the optional is empty
	 *
	 * @param encryptedPrivateKeyFile
	 *            the file that contains the password protected private key
	 * @param password
	 *            the password
	 * @return the {@link Optional} object with the password protected private key from the given
	 *         file or an empty {@link Optional} object if it does not match
	 * @throws OperatorCreationException
	 *             is thrown if an error occurs on the operator creation
	 * @throws PKCSException
	 *             is thrown if an error occurs on read the key file
	 */
	public static Optional<PrivateKey> getPrivateKey(final File encryptedPrivateKeyFile,
		final String password) throws OperatorCreationException, PKCSException
	{
		try
		{
			return Optional.of(readPasswordProtectedPrivateKey(encryptedPrivateKeyFile, password));
		}
		catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException
			| InvalidKeySpecException | InvalidKeyException
			| InvalidAlgorithmParameterException cannotBeOpened)
		{
			// the empty optional is this method's way of saying so; the reason is kept for anyone
			// who turns the log up rather than thrown, because the caller asked for an optional
			log.log(Level.FINE, "The file '" + encryptedPrivateKeyFile
				+ "' could not be opened as a password protected private key", cannotBeOpened);
			return Optional.empty();
		}
	}

	/**
	 * Reads from the given {@link File} that contains the password protected private key and
	 * returns it
	 *
	 * @param encryptedPrivateKeyFile
	 *            the file that contains the password protected private key
	 * @param password
	 *            the password
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails
	 * @throws PKCSException
	 *             is thrown if an error occurs on read the key file
	 */
	public static PrivateKey readPasswordProtectedPrivateKey(final File encryptedPrivateKeyFile,
		final String password, final String algorithm) throws IOException, NoSuchAlgorithmException,
		NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
		InvalidAlgorithmParameterException, PKCSException
	{
		PrivateKey privateKey = null;
		boolean pemFormat = PrivateKeyReader.isPemFormat(encryptedPrivateKeyFile);
		if (pemFormat)
		{
			// no null check needed: getKeyPair either returns a key pair or throws
			privateKey = getKeyPair(encryptedPrivateKeyFile, password).getPrivate();
		}
		else
		{
			byte[] encryptedPrivateKeyBytes = Files.readAllBytes(encryptedPrivateKeyFile.toPath());
			privateKey = readPasswordProtectedPrivateKey(encryptedPrivateKeyBytes, password,
				algorithm);
		}
		return privateKey;
	}
}
