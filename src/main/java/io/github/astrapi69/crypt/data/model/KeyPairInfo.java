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

import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Set;

import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeySizeExtensions;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

/**
 * Data class representing key pair information
 */
@Data
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class KeyPairInfo
{

	/**
	 * The name of the EC named curve parameter specification
	 */
	String eCNamedCurveParameterSpecName;

	/**
	 * The algorithm used for the key pair
	 */
	@NonNull
	String algorithm;

	/**
	 * The provider of the key pair
	 */
	String provider;

	/**
	 * The key size for the key pair
	 */
	int keySize;

	/**
	 * Factory method to create a new {@link KeyPair} object from the given {@link KeyPairInfo}
	 * object
	 *
	 * @param keyPairInfo
	 *            the {@link KeyPairInfo} object containing the key pair details
	 * @return the newly created {@link KeyPair} object
	 *
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 */
	public static KeyPair toKeyPair(@NonNull KeyPairInfo keyPairInfo)
		throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
	{
		return KeyPairFactory.newKeyPair(keyPairInfo);
	}

	/**
	 * Factory method to create a new {@link KeyPairInfo} object from the given {@link KeyPair}
	 * object
	 *
	 * @param keyPair
	 *            the {@link KeyPair} object containing the key pair details
	 * @return the newly created {@link KeyPairInfo} object
	 */
	public static KeyPairInfo toKeyPairInfo(@NonNull KeyPair keyPair)
	{
		return KeyPairInfo.builder()
			.keySize(PrivateKeyExtensions.getKeyLength(keyPair.getPrivate()))
			.algorithm(keyPair.getPrivate().getAlgorithm()).build();
	}

	/**
	 * Validation method to see if the given {@link KeyPairInfo} object is valid for creation
	 *
	 * @param keyPairInfo
	 *            the {@link KeyPairInfo} object containing the key pair details
	 * @return true if the given {@link KeyPairInfo} object is valid for creation otherwise false
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	public static boolean isValid(@NonNull KeyPairInfo keyPairInfo)
		throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
	{
		String keyGeneratorAlgorithm = keyPairInfo.getAlgorithm();
		boolean keyPairGenerator = AlgorithmExtensions.isValid("KeyPairGenerator",
			keyGeneratorAlgorithm);
		if (keyPairGenerator)
		{
			return false;
		}
		Set<Integer> supportedKeySizes = KeySizeExtensions.getSupportedKeySizes(
			keyGeneratorAlgorithm, KeyPairGenerator.class, KeyPairGenerator::initialize,
			keyPairInfo.getKeySize() - 1, keyPairInfo.getKeySize() + 1, 1);
		return supportedKeySizes.contains(keyPairInfo.getKeySize());
	}

}
