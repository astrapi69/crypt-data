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

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

/**
 * The factory class {@link KemFactory} holds methods for key encapsulation and decapsulation with
 * any algorithm supported by {@link KEM#getInstance(String)} (e.g. {@code "ML-KEM-768"}, the
 * NIST-standardized post-quantum key encapsulation mechanism defined in FIPS 203). Unlike Diffie-
 * Hellman-style key agreement (see {@link KeyAgreementFactory}), a KEM is one-directional: the
 * sender only needs the recipient's public key to produce a shared secret and a ciphertext to send;
 * no keypair or interaction is required on the sender's side.
 * <p>
 * Algorithms not natively supported by the JDK (such as {@code "ML-KEM-*"}) require a security
 * provider that implements them, e.g. Bouncy Castle, registered by the caller (
 * {@code Security.addProvider(new BouncyCastleProvider())}) before use.
 */
public final class KemFactory
{

	private KemFactory()
	{
	}

	/**
	 * Encapsulates a fresh shared secret for the given recipient public key.
	 *
	 * @param recipientPublicKey
	 *            the recipient's public key
	 * @param algorithm
	 *            the KEM algorithm, e.g. {@code "ML-KEM-768"}
	 * @return the encapsulated result, holding both the shared secret
	 *         ({@link KEM.Encapsulated#key()}) and the ciphertext to send to the recipient
	 *         ({@link KEM.Encapsulated#encapsulation()})
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no provider supports the given algorithm
	 * @throws InvalidKeyException
	 *             is thrown if the given public key is invalid for the given algorithm
	 */
	public static KEM.Encapsulated encapsulate(final PublicKey recipientPublicKey,
		final String algorithm) throws NoSuchAlgorithmException, InvalidKeyException
	{
		final KEM kem = KEM.getInstance(algorithm);
		final KEM.Encapsulator encapsulator = kem.newEncapsulator(recipientPublicKey);
		return encapsulator.encapsulate();
	}

	/**
	 * Decapsulates the shared secret from the given ciphertext with the recipient's private key.
	 *
	 * @param recipientPrivateKey
	 *            the recipient's private key
	 * @param encapsulation
	 *            the ciphertext produced by {@link #encapsulate(PublicKey, String)}
	 * @param algorithm
	 *            the KEM algorithm, e.g. {@code "ML-KEM-768"}
	 * @return the same shared secret produced by the corresponding
	 *         {@link #encapsulate(PublicKey, String)} call
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no provider supports the given algorithm
	 * @throws InvalidKeyException
	 *             is thrown if the given private key is invalid for the given algorithm
	 * @throws DecapsulateException
	 *             is thrown if the given ciphertext is malformed or does not match the private key
	 */
	public static SecretKey decapsulate(final PrivateKey recipientPrivateKey,
		final byte[] encapsulation, final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
	{
		final KEM kem = KEM.getInstance(algorithm);
		final KEM.Decapsulator decapsulator = kem.newDecapsulator(recipientPrivateKey);
		return decapsulator.decapsulate(encapsulation);
	}

}
