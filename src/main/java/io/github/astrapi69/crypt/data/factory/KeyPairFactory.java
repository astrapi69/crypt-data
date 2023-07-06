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
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;

/**
 * The factory class {@link KeyPairFactory} holds methods for creating {@link KeyPair} objects.
 */
public final class KeyPairFactory
{

	private KeyPairFactory()
	{
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given algorithm and key size.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @return the new {@link KeyPair} from the given salt and iteration count
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static KeyPair newKeyPair(final Algorithm algorithm, final int keySize)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return newKeyPair(algorithm.getAlgorithm(), keySize);
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given algorithm and
	 * {@link KeySize}
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size as enum
	 * @return the new {@link KeyPair} from the given salt and iteration count
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static KeyPair newKeyPair(final Algorithm algorithm, final KeySize keySize)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return newKeyPair(algorithm.getAlgorithm(), keySize.getKeySize());
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given parameters.
	 *
	 * @param publicKeyDerFile
	 *            the public key der file
	 * @param privateKeyDerFile
	 *            the private key der file
	 * @return the new {@link KeyPair} from the given parameters.
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static KeyPair newKeyPair(final File publicKeyDerFile, final File privateKeyDerFile)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
		IOException
	{
		final PublicKey publicKey = PublicKeyReader.readPublicKey(publicKeyDerFile);
		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);
		return newKeyPair(publicKey, privateKey);
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given private key
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new {@link KeyPair} from the given parameters
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws InvalidKeySpecException
	 *             the invalid key spec exception
	 */
	public static KeyPair newKeyPair(final PrivateKey privateKey)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		final KeyPair keyPair = new KeyPair(PrivateKeyExtensions.generatePublicKey(privateKey),
			privateKey);
		return keyPair;
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given parameters.
	 *
	 * @param publicKey
	 *            the public key
	 * @param privateKey
	 *            the private key
	 * @return the new {@link KeyPair} from the given parameters.
	 */
	public static KeyPair newKeyPair(final PublicKey publicKey, final PrivateKey privateKey)
	{
		final KeyPair keyPair = new KeyPair(publicKey, privateKey);
		return keyPair;
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given parameters.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @return the new {@link KeyPair} from the given parameters
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static KeyPair newKeyPair(final String algorithm, final int keySize)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		final KeyPairGenerator generator = KeyPairGeneratorFactory.newKeyPairGenerator(algorithm,
			keySize);
		return generator.generateKeyPair();
	}

	public static KeyPair generateECKeys()
	{
		try
		{
			ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable
				.getParameterSpec("brainpoolp256r1");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");

			keyPairGenerator.initialize(parameterSpec);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			return keyPair;
		}
		catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
			| NoSuchProviderException e)
		{
			e.printStackTrace();
			return null;
		}
	}

}
