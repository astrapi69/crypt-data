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

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import lombok.NonNull;

/**
 * The factory class {@link SecretKeyFactoryExtensions} holds methods for creating
 * {@link SecretKeySpec} objects
 */
public final class SecretKeyFactoryExtensions
{

	private SecretKeyFactoryExtensions()
	{
	}

	/**
	 * Factory method for creating a new {@link SecretKey} from the given password and algorithm
	 *
	 * @param password
	 *            the password
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link SecretKey} from the given password and algorithm
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             if generation of the SecretKey object fails
	 */
	public static SecretKey newSecretKey(final char[] password, final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		final PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
		final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
		final SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
		return secretKey;
	}

	/**
	 * Factory method for creating a new {@link SecretKeyFactory} from the given algorithm
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link SecretKeyFactory} from the given algorithm
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 */
	public static SecretKeyFactory newSecretKeyFactory(final @NonNull String algorithm)
		throws NoSuchAlgorithmException
	{
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
		return factory;
	}

	/**
	 * Factory method for creating a new {@link SecretKeyFactory} from the given algorithm
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param provider
	 *            the provider
	 * @return the new {@link SecretKeyFactory} from the given algorithm
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 */
	public static SecretKeyFactory newSecretKeyFactory(final @NonNull String algorithm,
		final String provider) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		final SecretKeyFactory factory = provider == null || provider.isEmpty()
			? newSecretKeyFactory(algorithm)
			: SecretKeyFactory.getInstance(algorithm, provider);
		return factory;
	}

	/**
	 * Factory method for creating a new symmetric {@link SecretKey} from the given algorithm and
	 * the given key length
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keyLength
	 *            the key length
	 * @return the new {@link SecretKey} from the given algorithm and the given key length
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 */
	public static SecretKey newSecretKey(final String algorithm, final int keyLength)
		throws NoSuchAlgorithmException
	{
		final KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		keyGenerator.init(keyLength);
		return keyGenerator.generateKey();
	}

	/**
	 * Factory method for creating a new {@link SecretKey} object from the given shared secret key
	 * as byte array and the given algorithm for the secret key
	 *
	 * @param sharedSecret
	 *            the shared secret key as byte array
	 * @param secretKeyAlgorithm
	 *            the algorithm for the {@link SecretKey} object creation
	 * @return the new {@link SecretKey} from the given algorithm and the given key length
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             if generation of the SecretKey object fails
	 */
	public static SecretKey newSecretKey(byte[] sharedSecret, String secretKeyAlgorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
		SecretKeySpec secretKeySpec = KeySpecFactory.newSecretKeySpec(sharedSecret,
			secretKeyAlgorithm);
		SecretKey secretKey = secretKeyFactory.generateSecret(secretKeySpec);
		return secretKey;
	}

	/**
	 * Retrieves the set of supported key sizes for the specified cryptographic algorithm using a
	 * {@link KeyGenerator}.
	 *
	 * <p>
	 * This method initializes a {@link KeyGenerator} instance for the given algorithm and attempts
	 * to initialize it with key sizes from 112 bits to 8192 bits in increments of 64 bits. If the
	 * initialization succeeds, the key size is considered supported and is added to the set of
	 * supported key sizes. If the initialization fails with an {@link InvalidParameterException},
	 * the key size is considered unsupported and is not added to the set.
	 *
	 * @param algorithm
	 *            the name of the cryptographic algorithm (e.g., "AES", "DES")
	 * @return a set of supported key sizes for the specified algorithm
	 * @throws NoSuchAlgorithmException
	 *             if no provider supports a {@link KeyGenerator} for the specified algorithm
	 */
	public static Set<Integer> getSupportedKeySizesForKeyGenerator(String algorithm)
		throws NoSuchAlgorithmException
	{
		Set<Integer> supportedKeySizes = new LinkedHashSet<>();
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		for (int i = 1; i <= 8192; i += 1)
		{
			try
			{
				keyGenerator.init(i);
				keyGenerator.generateKey();
				supportedKeySizes.add(i);
			}
			catch (InvalidParameterException e)
			{
				// Key size not supported
			}
		}
		return supportedKeySizes;
	}
}
