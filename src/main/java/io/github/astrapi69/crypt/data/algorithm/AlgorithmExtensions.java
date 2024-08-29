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
package io.github.astrapi69.crypt.data.algorithm;

import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import io.github.astrapi69.crypt.data.key.KeySizeExtensions;
import io.github.astrapi69.crypt.data.key.KeySizeInitializer;
import lombok.NonNull;

/**
 * The class {@code AlgorithmExtensions} provides methods to validate if a given algorithm is
 * supported for a specific service and to retrieve the supported algorithms for a service
 */
public final class AlgorithmExtensions
{
	private AlgorithmExtensions()
	{
	}

	/**
	 * Retrieves a map of supported cryptographic algorithms and their corresponding supported key
	 * sizes for a specified service.
	 *
	 * <p>
	 * This method identifies the available algorithms for a given cryptographic service (e.g.,
	 * "KeyPairGenerator") and determines the supported key sizes for each algorithm within a
	 * specified range. The determination is based on the capabilities of a provided generator class
	 * and an initializer.
	 *
	 * @param <T>
	 *            the type of the generator class used to determine key sizes.
	 * @param serviceName
	 *            the name of the cryptographic service (e.g., "KeyPairGenerator").
	 * @param generatorClass
	 *            the class of the generator used to produce cryptographic keys.
	 * @param initializer
	 *            a functional interface or lambda expression that initializes the generator class
	 *            with a specific key size.
	 * @param minSize
	 *            the minimum key size to consider in the analysis.
	 * @param maxSize
	 *            the maximum key size to consider in the analysis.
	 * @param increment
	 *            the step size for iterating through key sizes between minSize and maxSize.
	 * @return a {@code Map<String, Set<Integer>>} where each key is the name of a cryptographic
	 *         algorithm, and each value is a set of integers representing the supported key sizes
	 *         for that algorithm.
	 * @throws InvocationTargetException
	 *             if an error occurs while invoking the initializer or generator methods.
	 * @throws NoSuchMethodException
	 *             if a necessary method to initialize the generator class cannot be found.
	 * @throws IllegalAccessException
	 *             if the initializer or generator method is not accessible.
	 */
	public static <T> Map<String, Set<Integer>> getSupportedAlgorithmsAndKeySizes(
		String serviceName, Class<T> generatorClass, KeySizeInitializer<T> initializer, int minSize,
		int maxSize, int increment)
		throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
	{
		Map<String, Set<Integer>> supportedKeySizesMap = new TreeMap<>();
		Set<String> algorithms = AlgorithmExtensions.getAlgorithms(serviceName);
		for (String algorithm : algorithms)
		{
			Set<Integer> supportedKeySizes = KeySizeExtensions.getSupportedKeySizes(algorithm,
				generatorClass, initializer, minSize, maxSize, increment);
			supportedKeySizesMap.put(algorithm, supportedKeySizes);
		}
		return supportedKeySizesMap;
	}

	/**
	 * Retrieves a list of algorithms that are appropriate for the specified key algorithm based on
	 * the provided service name
	 *
	 * @param serviceName
	 *            the name of the service, for instance "Signature"
	 * @param keyAlgorithm
	 *            the key algorithm (e.g., "RSA") for which to find appropriate signature algorithms
	 * @return a list of algorithms that match the specified key algorithm
	 */
	public static List<String> getAlgorithmsFromServiceName(final @NonNull String serviceName,
		final @NonNull String keyAlgorithm)
	{
		Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms(serviceName);
		List<String> appropriateAlgorithms = signatureAlgorithms.stream()
			.filter(signatureAlgorithm -> signatureAlgorithm.contains(keyAlgorithm))
			.collect(Collectors.toList());
		return appropriateAlgorithms;
	}

	/**
	 * Validates if the provided algorithm is supported for the given service name
	 *
	 * @param serviceName
	 *            the name of the security service
	 * @param algorithm
	 *            the algorithm to be validated
	 * @return true if the algorithm is supported, false otherwise
	 */
	public static boolean isValid(final @NonNull String serviceName,
		final @NonNull String algorithm)
	{
		Set<String> algorithms = getAlgorithms(serviceName);
		return algorithms.contains(algorithm);
	}

	/**
	 * Retrieves a set of algorithms for the specified Java cryptographic service
	 *
	 * <p>
	 * This method calls the {@link Security#getAlgorithms(String)} method to obtain a set of
	 * algorithm names supported by the specified security service
	 * </p>
	 *
	 * @param serviceName
	 *            the name of the security service (e.g., "Cipher", "KeyAgreement", "MessageDigest",
	 *            etc.) for which the supported algorithms are to be retrieved
	 * @return a {@link Set} of {@link String} containing the names of the algorithms supported by
	 *         the specified security service. The set is not modifiable
	 * @throws NullPointerException
	 *             if {@code serviceName} is null
	 * @see Security#getAlgorithms(String)
	 */
	public static Set<String> getAlgorithms(final @NonNull String serviceName)
	{
		return Security.getAlgorithms(serviceName);
	}

	/**
	 * Retrieves all specified Java cryptographic service names from the given {@link Provider}
	 * object
	 *
	 * @param provider
	 *            the {@link Provider} object
	 * @return a set of all specified Java cryptographic service names from the given
	 *         {@link Provider} object
	 */
	public static Set<String> getServiceNames(final @NonNull Provider provider)
	{
		Set<String> serviceNames = new HashSet<>();
		for (Provider.Service service : provider.getServices())
		{
			serviceNames.add(service.getType());
		}
		return serviceNames;
	}

	/**
	 * Retrieves all specified Java cryptographic service names from the given {@link Provider}
	 * array object
	 *
	 * @param providers
	 *            the array with the {@link Provider} objects
	 * @return a set of all specified Java cryptographic service names
	 */
	public static Set<String> getAllServiceNames(Provider[] providers)
	{
		Set<String> serviceNames = new HashSet<>();
		for (Provider provider : providers)
		{
			serviceNames.addAll(getServiceNames(provider));
		}
		return serviceNames;
	}
}
