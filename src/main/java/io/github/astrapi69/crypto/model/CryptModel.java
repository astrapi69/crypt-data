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
package io.github.astrapi69.crypto.model;

import java.io.Serializable;
import java.util.List;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Singular;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;
import io.github.astrapi69.crypto.algorithm.Algorithm;

/**
 * The class {@link CryptModel} holds data for the encryption or decryption process.
 *
 * @param <C>
 *            the generic type of the cipher
 * @param <K>
 *            the generic type of the key
 * @param <T>
 *            the generic type of the decorator objects
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
public class CryptModel<C, K, T> implements Serializable
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The algorithm. */
	Algorithm algorithm;

	/** The cipher. */
	C cipher;

	/** The decorators for the crypt object */
	@Singular
	List<CryptObjectDecorator<T>> decorators;

	/**
	 * The flag initialized that indicates if the cipher is initialized.
	 */
	boolean initialized;

	/** The iteration count. */
	Integer iterationCount;

	/**
	 * The key. Can be a string like password or an object like public or private key
	 */
	K key;

	/** The operation mode that indicates if an encryption or decryption process will start. */
	int operationMode;

	/** The salt byte array. */
	byte[] salt;

	/**
	 * Factory method for create a new {@link CryptModel} from the given key
	 *
	 * @param <C>
	 *            the generic type of the cipher
	 * @param <K>
	 *            the generic type of the key
	 * @param <T>
	 *            the generic type of the decorator objects
	 * @param key
	 *            the key
	 * @return the new created {@link CryptModel} object
	 */
	public static <C, K, T> CryptModel<C, K, T> of(K key)
	{
		return CryptModel.<C, K, T> builder().key(key).build();
	}
}
