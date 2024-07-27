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

import java.security.Security;
import java.util.Set;

import lombok.NonNull;

/**
 * The class {@code AlgorithmValidator} provides a method to validate if a given algorithm is
 * supported for a specific service
 */
public class AlgorithmValidator
{

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
		Set<String> algorithms = Security.getAlgorithms(serviceName);
		return algorithms.contains(algorithm);
	}
}
