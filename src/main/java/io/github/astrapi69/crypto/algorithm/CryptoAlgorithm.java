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
package io.github.astrapi69.crypto.algorithm;

import de.alpharogroup.crypto.algorithm.Algorithm;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

/**
 * The class {@link CryptoAlgorithm} provides factory method for create an algorithm from string for
 * encryption or decryption.
 */
@Data
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CryptoAlgorithm implements Algorithm
{
	/** the algorithm */
	String algorithm;

	/**
	 * Private constructor
	 * 
	 * @param algorithm
	 *            the algorithm
	 */
	private CryptoAlgorithm(@NonNull String algorithm)
	{
		this.algorithm = algorithm;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getAlgorithm()
	{
		return this.algorithm;
	}

	/**
	 * Gets the name of this algorithm
	 * 
	 * @return the name of this algorithm
	 */
	public String name()
	{
		return this.algorithm;
	}

	/**
	 * Factory method for creating a new {@link Algorithm} from the given string algorithm
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link Algorithm}
	 */
	public static Algorithm newAlgorithm(@NonNull String algorithm)
	{
		return new CryptoAlgorithm(algorithm);
	}
}
