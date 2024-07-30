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
package io.github.astrapi69.crypt.data.key;

import java.lang.reflect.InvocationTargetException;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.crypto.KeyGenerator;

/**
 * The class {@link KeySizeExtensions} provides methods to retrieve supported key sizes for various
 * cryptographic algorithms using different cryptographic service types
 */
public class KeySizeExtensions
{

	/**
	 * Generic method to determine supported key sizes for a cryptographic service
	 *
	 * @param <T>
	 *            the type of the generator
	 * @param algorithm
	 *            the name of the cryptographic algorithm (e.g., "RSA", "AES")
	 * @param generatorClass
	 *            the class type of the generator (e.g., KeyPairGenerator.class)
	 * @param initializer
	 *            a lambda expression to initialize the generator with the specified key size
	 * @param minSize
	 *            the minimum key size to test
	 * @param maxSize
	 *            the maximum key size to test
	 * @param increment
	 *            the increment step for the key size
	 * @return a set of supported key sizes for the specified algorithm
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	@SuppressWarnings("unchecked")
	public static <T> Set<Integer> getSupportedKeySizes(String algorithm, Class<T> generatorClass,
		KeySizeInitializer<T> initializer, int minSize, int maxSize, int increment)
		throws NoSuchMethodException, InvocationTargetException, IllegalAccessException
	{
		Set<Integer> supportedKeySizes = new LinkedHashSet<>();
		T generator = (T)generatorClass.getDeclaredMethod("getInstance", String.class).invoke(null,
			algorithm);
		for (int i = minSize; i <= maxSize; i += increment)
		{
			try
			{
				initializer.initialize(generator, i);
				supportedKeySizes.add(i);
			}
			catch (InvalidParameterException e)
			{
				// Key size not supported
			}
		}
		return supportedKeySizes;
	}

	/**
	 * Retrieves the set of supported key sizes for the specified cryptographic algorithm using a
	 * {@link KeyGenerator}
	 * <p>
	 * This method initializes a {@link KeyGenerator} instance for the given algorithm and attempts
	 * to initialize it with key sizes from 112 bits to 8192 bits in increments of 64 bits. If the
	 * initialization succeeds, the key size is considered supported and is added to the set of
	 * supported key sizes. If the initialization fails with an {@link InvalidParameterException},
	 * the key size is considered unsupported and is not added to the set
	 *
	 * @param algorithm
	 *            the name of the cryptographic algorithm (e.g., "AES", "DES")
	 * @return a set of supported key sizes for the specified algorithm
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	public static Set<Integer> getSupportedKeySizesForAlgorithmParameterGenerator(String algorithm)
		throws NoSuchMethodException, InvocationTargetException, IllegalAccessException
	{
		return KeySizeExtensions.getSupportedKeySizes(algorithm, AlgorithmParameterGenerator.class,
			(generator, keySize) -> ((AlgorithmParameterGenerator)generator).init(keySize), 1, 8192,
			1);
	}

	/**
	 * Retrieves the set of supported key sizes for the specified cryptographic algorithm using a
	 * {@link KeyPairGenerator}
	 * <p>
	 * This method initializes a {@link KeyPairGenerator} instance for the given algorithm and
	 * attempts to initialize it with key sizes from 512 bits to 8192 bits in increments of 64 bits.
	 * If the initialization succeeds, the key size is considered supported and is added to the set
	 * of supported key sizes. If the initialization fails with an
	 * {@link InvalidParameterException}, the key size is considered unsupported and is not added to
	 * the set
	 *
	 * @param algorithm
	 *            the name of the cryptographic algorithm (e.g., "RSA", "DSA")
	 * @return a set of supported key sizes for the specified algorithm
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	public static Set<Integer> getSupportedKeySizesForKeyPairGenerator(String algorithm)
		throws NoSuchMethodException, InvocationTargetException, IllegalAccessException
	{
		return KeySizeExtensions.getSupportedKeySizes(algorithm, KeyPairGenerator.class,
			KeyPairGenerator::initialize, 512, 8192, 64);
	}

	/**
	 * Retrieves the set of supported key sizes for the specified cryptographic algorithm using a
	 * {@link KeyGenerator}
	 * <p>
	 * This method initializes a {@link KeyGenerator} instance for the given algorithm and attempts
	 * to initialize it with key sizes from 112 bits to 8192 bits in increments of 64 bits. If the
	 * initialization succeeds, the key size is considered supported and is added to the set of
	 * supported key sizes. If the initialization fails with an {@link InvalidParameterException},
	 * the key size is considered unsupported and is not added to the set
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
