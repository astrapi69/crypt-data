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

import java.security.InvalidParameterException;
import java.util.Arrays;

import io.github.astrapi69.crypt.data.key.KeySizeExtensions;
import io.github.astrapi69.crypt.data.key.KeySizeInitializer;

/**
 * Test double for the generator class that
 * {@link KeySizeExtensions#getSupportedKeySizes(String, Class, KeySizeInitializer, int, int, int)}
 * instantiates reflectively. It offers the static {@code getInstance(String)} factory the
 * reflection expects but performs no cryptography, so key-size probing over all registered
 * algorithms stays fast and deterministic. Which algorithm/key-size combinations count as
 * "supported" is decided by the {@link KeySizeInitializer} returned from
 * {@link #accepting(String, int...)}
 */
public final class KeySizeProbe
{

	private final String algorithm;

	private KeySizeProbe(final String algorithm)
	{
		this.algorithm = algorithm;
	}

	/**
	 * The factory method the reflective lookup in {@link KeySizeExtensions} resolves
	 *
	 * @param algorithm
	 *            the algorithm name the probe stands for
	 * @return a new probe for the given algorithm
	 */
	public static KeySizeProbe getInstance(final String algorithm)
	{
		return new KeySizeProbe(algorithm);
	}

	/**
	 * Gets the algorithm name this probe stands for
	 *
	 * @return the algorithm name
	 */
	public String getAlgorithm()
	{
		return algorithm;
	}

	/**
	 * Creates an initializer that accepts only the given algorithm with the given key sizes and
	 * rejects everything else with an {@link InvalidParameterException}, exactly like a real
	 * generator rejects an unsupported key size
	 *
	 * @param acceptedAlgorithm
	 *            the only algorithm name that is accepted
	 * @param acceptedKeySizes
	 *            the only key sizes that are accepted for that algorithm
	 * @return the initializer
	 */
	public static KeySizeInitializer<KeySizeProbe> accepting(final String acceptedAlgorithm,
		final int... acceptedKeySizes)
	{
		return (probe, keySize) -> {
			boolean algorithmAccepted = acceptedAlgorithm.equals(probe.getAlgorithm());
			boolean keySizeAccepted = Arrays.stream(acceptedKeySizes)
				.anyMatch(accepted -> accepted == keySize);
			if (!algorithmAccepted || !keySizeAccepted)
			{
				throw new InvalidParameterException(
					"rejected " + probe.getAlgorithm() + " with key size " + keySize);
			}
		};
	}
}
