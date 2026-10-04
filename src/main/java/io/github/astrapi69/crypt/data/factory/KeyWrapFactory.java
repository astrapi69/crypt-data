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
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * The factory class {@link KeyWrapFactory} holds methods for wrapping (encrypting) and unwrapping
 * (decrypting) cryptographic keys with another key, using the AES Key Wrap algorithm defined in RFC
 * 3394. Unlike a plain {@link Cipher#ENCRYPT_MODE}/{@link Cipher#DECRYPT_MODE} transformation, key
 * wrapping also provides an implicit integrity check: unwrapping tampered or corrupted wrapped
 * bytes fails with an {@link InvalidKeyException} rather than silently returning garbage key
 * material. AES Key Wrap is natively supported by the JDK (SunJCE), no Bouncy Castle needed.
 */
public final class KeyWrapFactory
{

	/** The AES Key Wrap (RFC 3394) transformation name. */
	private static final String AES_WRAP_ALGORITHM = "AESWrap";

	private KeyWrapFactory()
	{
	}

	/**
	 * Wraps (encrypts) the given key with the given key-encryption key.
	 *
	 * @param keyEncryptionKey
	 *            the AES key used to wrap the given key
	 * @param keyToWrap
	 *            the key to wrap
	 * @return the wrapped key bytes
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the {@link Cipher} object fails
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the {@link Cipher} object fails
	 * @throws InvalidKeyException
	 *             is thrown if the given key-encryption key is invalid
	 * @throws IllegalBlockSizeException
	 *             is thrown if the given key cannot be wrapped
	 */
	public static byte[] wrap(final SecretKey keyEncryptionKey, final Key keyToWrap)
		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
		IllegalBlockSizeException
	{
		final Cipher cipher = Cipher.getInstance(AES_WRAP_ALGORITHM);
		cipher.init(Cipher.WRAP_MODE, keyEncryptionKey);
		return cipher.wrap(keyToWrap);
	}

	/**
	 * Unwraps (decrypts) the given wrapped key bytes with the given key-encryption key.
	 *
	 * @param keyEncryptionKey
	 *            the AES key that was used to wrap the key
	 * @param wrappedKey
	 *            the wrapped key bytes
	 * @param wrappedKeyAlgorithm
	 *            the algorithm of the unwrapped key, e.g. {@code "AES"}
	 * @param wrappedKeyType
	 *            the type of the unwrapped key, one of {@link Cipher#SECRET_KEY},
	 *            {@link Cipher#PRIVATE_KEY} or {@link Cipher#PUBLIC_KEY}
	 * @return the unwrapped key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the {@link Cipher} object fails, or if the
	 *             unwrapped key algorithm is not recognized
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the {@link Cipher} object fails
	 * @throws InvalidKeyException
	 *             is thrown if the given key-encryption key is invalid, or if the wrapped key bytes
	 *             are malformed or tampered with (the integrity check fails)
	 */
	public static Key unwrap(final SecretKey keyEncryptionKey, final byte[] wrappedKey,
		final String wrappedKeyAlgorithm, final int wrappedKeyType)
		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
	{
		final Cipher cipher = Cipher.getInstance(AES_WRAP_ALGORITHM);
		cipher.init(Cipher.UNWRAP_MODE, keyEncryptionKey);
		return cipher.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
	}

}
