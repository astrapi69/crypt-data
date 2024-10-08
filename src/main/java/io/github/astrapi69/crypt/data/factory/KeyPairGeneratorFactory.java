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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import io.github.astrapi69.crypt.api.provider.SecurityProvider;

/**
 * The factory class {@link KeyPairGeneratorFactory} provides methods for creating
 * {@link KeyPairGenerator} objects
 */
public final class KeyPairGeneratorFactory
{

	private KeyPairGeneratorFactory()
	{
	}

	/**
	 * Factory method for creating a new {@link KeyPairGenerator} with the specified algorithm
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link KeyPairGenerator} with the specified algorithm
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 */
	public static KeyPairGenerator newKeyPairGenerator(final String algorithm)
		throws NoSuchAlgorithmException
	{
		return KeyPairGenerator.getInstance(algorithm);
	}

	/**
	 * Factory method for creating a new {@link KeyPairGenerator} with the specified algorithm and
	 * provider
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param provider
	 *            the provider
	 * @return the new {@link KeyPairGenerator} with the specified algorithm and provider
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 */
	public static KeyPairGenerator newKeyPairGenerator(final String algorithm,
		final String provider) throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return KeyPairGenerator.getInstance(algorithm, provider);
	}

	/**
	 * Factory method for creating a new {@link KeyPairGenerator} with the specified algorithm and
	 * key size
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @return the new {@link KeyPairGenerator} with the specified algorithm and key size
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 */
	public static KeyPairGenerator newKeyPairGenerator(final String algorithm, final int keySize)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPairGenerator generator;
		if ("EC".equals(algorithm))
		{
			generator = newKeyPairGenerator(algorithm, SecurityProvider.BC.name());
		}
		else
		{
			generator = newKeyPairGenerator(algorithm);
			generator.initialize(keySize);
		}
		return generator;
	}

	/**
	 * Factory method for creating a new {@link KeyPairGenerator} with the specified algorithm, key
	 * size, and {@link SecureRandom}
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @param secureRandom
	 *            the secure random
	 * @return the new {@link KeyPairGenerator} with the specified algorithm, key size, and
	 *         {@link SecureRandom}
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 */
	public static KeyPairGenerator newKeyPairGenerator(final String algorithm, final int keySize,
		final SecureRandom secureRandom) throws NoSuchAlgorithmException
	{
		final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		generator.initialize(keySize, secureRandom);
		return generator;
	}

	/**
	 * Factory method for creating a new {@link KeyPairGenerator} with the specified elliptic curve,
	 * algorithm, and provider
	 *
	 * @param eCNamedCurveParameterSpecName
	 *            the name of the elliptic curve
	 * @param algorithm
	 *            the algorithm
	 * @param provider
	 *            the provider
	 * @return the new {@link KeyPairGenerator} with the specified elliptic curve, algorithm, and
	 *         provider
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 */
	public static KeyPairGenerator newKeyPairGenerator(String eCNamedCurveParameterSpecName,
		final String algorithm, final String provider)
		throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		return newKeyPairGenerator(
			ECNamedCurveTable.getParameterSpec(eCNamedCurveParameterSpecName), algorithm, provider);
	}

	/**
	 * Factory method for creating a new {@link KeyPairGenerator} with the specified elliptic curve
	 * parameter spec, algorithm, and provider
	 *
	 * @param namedCurveParameterSpec
	 *            the elliptic curve parameter spec
	 * @param algorithm
	 *            the algorithm
	 * @param provider
	 *            the provider
	 * @return the new {@link KeyPairGenerator} with the specified elliptic curve parameter spec,
	 *         algorithm, and provider
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 */
	public static KeyPairGenerator newKeyPairGenerator(
		ECNamedCurveParameterSpec namedCurveParameterSpec, final String algorithm,
		final String provider)
		throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, provider);
		generator.initialize(namedCurveParameterSpec);
		return generator;
	}
}
