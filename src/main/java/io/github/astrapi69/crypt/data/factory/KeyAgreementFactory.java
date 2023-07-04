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

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * The factory class {@link KeyAgreementFactory} holds methods for creating new shared
 * {@link SecretKey} objects and {@link KeyAgreement} objects
 */
public class KeyAgreementFactory
{

	/**
	 * Factory method for creating a new shared {@link SecretKey} object from the given arguments
	 *
	 * @param privateKey
	 *            the private key
	 * @param publicKey
	 *            the public key
	 * @param keyAgreementAlgorithm
	 *            the key agreement algorithm
	 * @param secretKeyAlgorithm
	 *            the secret key algorithm
	 * @param provider
	 *            the provider
	 * @param lastPhase
	 *            the last phase flag which indicates whether this is the last phase of the key
	 *            agreement that will be created
	 * @return the new created shared {@link SecretKey} object from the given arguments
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static SecretKey newSharedSecret(PrivateKey privateKey, PublicKey publicKey,
		String keyAgreementAlgorithm, String secretKeyAlgorithm, String provider, boolean lastPhase)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyAgreement keyAgreement = newKeyAgreement(privateKey, publicKey, keyAgreementAlgorithm,
			provider, lastPhase);

		return keyAgreement.generateSecret(secretKeyAlgorithm);
	}


	/**
	 * Factory method for creating a new {@link KeyAgreement} object from the given arguments
	 *
	 * @param privateKey
	 *            the private key
	 * @param publicKey
	 *            the public key
	 * @param keyAgreementAlgorithm
	 *            the key agreement algorithm
	 * @param provider
	 *            the provider
	 * @param lastPhase
	 *            the last phase flag which indicates whether this is the last phase of the key
	 *            agreement that will be created
	 * @return the new created shared {@link KeyAgreement} object from the given arguments
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static KeyAgreement newKeyAgreement(PrivateKey privateKey, PublicKey publicKey,
		String keyAgreementAlgorithm, String provider, boolean lastPhase)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyAgreement keyAgreement = provider != null
			? KeyAgreement.getInstance(keyAgreementAlgorithm, provider)
			: KeyAgreement.getInstance(keyAgreementAlgorithm);
		keyAgreement.init(privateKey);
		keyAgreement.doPhase(publicKey, lastPhase);

		return keyAgreement;
	}
}
