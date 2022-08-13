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
package io.github.astrapi69.crypt.data.key.writer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import io.github.astrapi69.crypt.data.factory.AlgorithmParameterSpecFactory;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypto.algorithm.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypto.compound.CompoundAlgorithm;

/**
 * The class {@link EncryptedPrivateKeyWriter} is a utility class for write and protect
 * {@link PrivateKey} objects with a password to files.
 *
 * @author Asterios Raptis
 */
public final class EncryptedPrivateKeyWriter
{

	private EncryptedPrivateKeyWriter()
	{
	}

	/**
	 * Encrypt the given {@link PrivateKey} with the given password and write the result to the
	 * given {@link File}.
	 *
	 * @param privateKey
	 *            the private key to encrypt
	 * @param file
	 *            the file
	 * @param password
	 *            the password
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             the illegal block size exception
	 * @throws BadPaddingException
	 *             is thrown when a particular padding mechanism is expected for the input data but
	 *             the data is not padded properly.
	 * @throws InvalidParameterSpecException
	 *             the invalid parameter spec exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static void encryptPrivateKeyWithPassword(final PrivateKey privateKey, final File file,
		final String password) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
		IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, IOException
	{
		encryptPrivateKeyWithPassword(privateKey, new FileOutputStream(file), password);
	}

	/**
	 * Encrypt the given {@link PrivateKey} with the given password and write the result to the
	 * given {@link OutputStream}.
	 *
	 * @param privateKey
	 *            the private key to encrypt
	 * @param outputStream
	 *            the output stream
	 * @param password
	 *            the password
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             the illegal block size exception
	 * @throws BadPaddingException
	 *             is thrown when a particular padding mechanism is expected for the input data but
	 *             the data is not padded properly.
	 * @throws InvalidParameterSpecException
	 *             the invalid parameter spec exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void encryptPrivateKeyWithPassword(final PrivateKey privateKey,
		final OutputStream outputStream, final String password)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
		BadPaddingException, InvalidParameterSpecException, IOException
	{
		Objects.requireNonNull(outputStream);
		final byte[] encryptedPrivateKeyWithPasswordBytes = encryptPrivateKeyWithPassword(
			privateKey, password);
		outputStream.write(encryptedPrivateKeyWithPasswordBytes);
		outputStream.close();
	}

	/**
	 * Encrypt the given {@link PrivateKey} with the given password and return the resulted byte
	 * array.
	 *
	 * @param privateKey
	 *            the private key to encrypt
	 * @param password
	 *            the password
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             the illegal block size exception
	 * @throws BadPaddingException
	 *             is thrown when a particular padding mechanism is expected for the input data but
	 *             the data is not padded properly.
	 * @throws InvalidParameterSpecException
	 *             the invalid parameter spec exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static byte[] encryptPrivateKeyWithPassword(final PrivateKey privateKey,
		final String password) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
		IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, IOException
	{
		final byte[] privateKeyEncoded = privateKey.getEncoded();

		final SecureRandom random = new SecureRandom();
		final byte[] salt = new byte[8];
		random.nextBytes(salt);

		final AlgorithmParameterSpec algorithmParameterSpec = AlgorithmParameterSpecFactory
			.newPBEParameterSpec(salt, 20);

		final SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(password.toCharArray(),
			CompoundAlgorithm.PBE_WITH_SHA1_AND_DES_EDE.getAlgorithm());

		final Cipher pbeCipher = Cipher
			.getInstance(CompoundAlgorithm.PBE_WITH_SHA1_AND_DES_EDE.getAlgorithm());

		pbeCipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);

		final byte[] ciphertext = pbeCipher.doFinal(privateKeyEncoded);

		final AlgorithmParameters algorithmParameters = AlgorithmParameters
			.getInstance(CompoundAlgorithm.PBE_WITH_SHA1_AND_DES_EDE.getAlgorithm());
		algorithmParameters.init(algorithmParameterSpec);
		final EncryptedPrivateKeyInfo encinfo = new EncryptedPrivateKeyInfo(algorithmParameters,
			ciphertext);

		return encinfo.getEncoded();
	}

	/**
	 * Gets the private key from the given encrypted byte array with the given password. This method
	 * is the counterpart of the method
	 * {@link EncryptedPrivateKeyWriter#encryptPrivateKeyWithPassword(PrivateKey, String)}
	 *
	 * @param derEncodedPkcs8byteArray
	 *            the DER encoded PKCS#8 encrypted key as byte array
	 * @param password
	 *            the password
	 * @return the private key from the given encrypted byte array with the given password
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 */
	public static PrivateKey getPasswordProtectedPrivateKey(byte[] derEncodedPkcs8byteArray,
		String password) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
		InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		EncryptedPrivateKeyInfo encryptPKInfo = new EncryptedPrivateKeyInfo(
			derEncodedPkcs8byteArray);

		Cipher cipher = Cipher.getInstance(encryptPKInfo.getAlgName());
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secFac = SecretKeyFactory.getInstance(encryptPKInfo.getAlgName());
		Key pbeKey = secFac.generateSecret(pbeKeySpec);
		AlgorithmParameters algParams = encryptPKInfo.getAlgParameters();
		cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
		KeySpec pkcs8KeySpec = encryptPKInfo.getKeySpec(cipher);
		KeyFactory kf = KeyFactory.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		return kf.generatePrivate(pkcs8KeySpec);
	}

}
