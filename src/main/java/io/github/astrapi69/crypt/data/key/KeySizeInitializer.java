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

import java.security.InvalidParameterException;

/**
 * The functional interface {@link KeySizeInitializer} provides a method for initializing a
 * cryptographic key generator with a specified key size
 *
 * @param <T>
 *            the type of the generator
 */
@FunctionalInterface
public interface KeySizeInitializer<T>
{
	/**
	 * Initializes the given generator with the specified key size
	 *
	 * @param generator
	 *            the cryptographic key generator
	 * @param keySize
	 *            the size of the key to initialize the generator with
	 * @throws InvalidParameterException
	 *             if the specified key size is invalid for the generator
	 */
	void initialize(T generator, int keySize) throws InvalidParameterException;
}
