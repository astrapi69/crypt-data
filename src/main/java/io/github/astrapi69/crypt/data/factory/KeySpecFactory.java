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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;

/**
 * The factory class {@link KeySpecFactory} holds methods for creating {@link KeySpec} objects
 */
public final class KeySpecFactory
{

	private KeySpecFactory()
	{
	}

	/**
	 * Factory method for creating a new {@link PBEKeySpec} from the given private key
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new {@link PBEKeySpec} from the given private key
	 */
	public static KeySpec newPBEKeySpec(final String privateKey)
	{
		if (privateKey == null)
		{
			return new PBEKeySpec(CompoundAlgorithm.PASSWORD.toCharArray());
		}
		return new PBEKeySpec(privateKey.toCharArray());
	}

	/**
	 * Factory method for creating a new {@link PBEKeySpec} from the given password, salt and the
	 * iteration count
	 *
	 * @param password
	 *            the password
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 * @return the new {@link PBEKeySpec} from the given password, salt and the iteration count
	 */
	public static KeySpec newPBEKeySpec(final String password, final byte[] salt,
		final int iterationCount)
	{
		if (password == null)
		{
			return new PBEKeySpec(CompoundAlgorithm.PASSWORD.toCharArray(), salt, iterationCount);
		}
		return new PBEKeySpec(password.toCharArray(), salt, iterationCount);
	}

	/**
	 * Factory method for creating a new {@link SecretKeySpec} from the given algorithm and the
	 * given secret key as byte array
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param secretKey
	 *            the secret key
	 * @return the new {@link SecretKeySpec} from the given algorithm and the given secret key
	 */
	public static SecretKeySpec newSecretKeySpec(final byte[] secretKey, final String algorithm)
	{
		final SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, algorithm);
		return secretKeySpec;
	}

	/**
	 * Factory method for creating a new {@link SecretKeySpec} from the given algorithm and the
	 * given secret key as byte array
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param offset
	 *            the offset in <code>key</code> where the key material starts
	 * @param len
	 *            the length of the key material
	 * @param secretKey
	 *            the secret key
	 * @return the new {@link SecretKeySpec} from the given algorithm and the given secret key
	 */
	public static SecretKeySpec newSecretKeySpec(final byte[] secretKey, int offset, int len,
		final String algorithm)
	{
		final SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, offset, len, algorithm);
		return secretKeySpec;
	}

	/**
	 * Factory method for creating a new {@link DESKeySpec} from the given secret key as byte array
	 *
	 * @param secretKey
	 *            the secret key
	 * @return the new {@link DESKeySpec} from the given secret key as byte array
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the {@link DESKeySpec} object fails
	 */
	public static DESKeySpec newDESKeySpec(final byte[] secretKey) throws InvalidKeyException
	{
		return new DESKeySpec(secretKey);
	}

	/**
	 * Factory method for creating a new {@link DESedeKeySpec} from the given secret key as byte
	 * array
	 *
	 * @param secretKey
	 *            the secret key
	 * @return the new {@link DESedeKeySpec} from the given secret key as byte array
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the {@link DESKeySpec} object fails
	 */
	public static DESedeKeySpec newDESedeKeySpec(final byte[] secretKey) throws InvalidKeyException
	{
		return new DESedeKeySpec(secretKey);
	}

	/**
	 * Factory method for creating a new {@link SecretKeySpec} from the given algorithm and the
	 * given key length
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keyLength
	 *            the key length
	 * @return the new {@link SecretKeySpec} from the given algorithm and the given key length
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 */
	public static SecretKeySpec newSecretKeySpec(final String algorithm, final int keyLength)
		throws NoSuchAlgorithmException
	{
		final SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(algorithm, keyLength);
		final byte[] secretKeyEncoded = secretKey.getEncoded();
		return newSecretKeySpec(secretKeyEncoded, algorithm);
	}

	/**
	 * Factory method for creating a new symmetric {@link SecretKey} from the given algorithm and
	 * the given key length
	 *
	 * @param decryptedKey
	 *            the symmetric key as byte array
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link SecretKey} from the given algorithm and the given key length
	 */
	public static SecretKey newSecretKey(byte[] decryptedKey, final String algorithm)
	{
		return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, algorithm);
	}

}
