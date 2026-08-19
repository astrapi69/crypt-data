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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * The factory class {@link SignatureFactory} holds methods for creating digital signatures and
 * verifying them, for any algorithm supported by {@link Signature#getInstance(String)} (e.g.
 * {@code "Ed25519"}, natively supported by the JDK, or the RSA signature transformations defined in
 * {@code CompoundAlgorithm}).
 */
public final class SignatureFactory
{

	private SignatureFactory()
	{
	}

	/**
	 * Signs the given data with the given private key and algorithm.
	 *
	 * @param privateKey
	 *            the private key
	 * @param algorithm
	 *            the signature algorithm, e.g. {@code "Ed25519"}
	 * @param data
	 *            the data to sign
	 * @return the signature bytes
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the {@link Signature} object fails
	 * @throws InvalidKeyException
	 *             is thrown if the given private key is invalid for the given algorithm
	 * @throws SignatureException
	 *             is thrown if the {@link Signature} object is not properly initialized
	 */
	public static byte[] sign(final PrivateKey privateKey, final String algorithm,
		final byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		final Signature signature = Signature.getInstance(algorithm);
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}

	/**
	 * Verifies the given signature over the given data with the given public key and algorithm.
	 *
	 * @param publicKey
	 *            the public key
	 * @param algorithm
	 *            the signature algorithm, e.g. {@code "Ed25519"}
	 * @param data
	 *            the data that was signed
	 * @param signatureBytes
	 *            the signature to verify
	 * @return true if the signature is valid for the given data and public key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the {@link Signature} object fails
	 * @throws InvalidKeyException
	 *             is thrown if the given public key is invalid for the given algorithm
	 * @throws SignatureException
	 *             is thrown if the {@link Signature} object is not properly initialized
	 */
	public static boolean verify(final PublicKey publicKey, final String algorithm,
		final byte[] data, final byte[] signatureBytes)
		throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		final Signature signature = Signature.getInstance(algorithm);
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(signatureBytes);
	}

}
