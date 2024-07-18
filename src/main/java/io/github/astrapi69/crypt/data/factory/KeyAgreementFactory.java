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
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.github.astrapi69.crypt.data.key.SharedSecretExtensions;
import io.github.astrapi69.crypt.data.model.SharedSecretInfo;
import io.github.astrapi69.crypt.data.model.SharedSecretModel;

/**
 * The factory class {@link KeyAgreementFactory} holds methods for creating new shared
 * {@link SecretKey} objects and {@link KeyAgreement} objects.
 */
public class KeyAgreementFactory
{

	/**
	 * Factory method for creating a new shared {@link SecretKey} object from the given arguments.
	 *
	 * @param sharedSecretModel
	 *            the {@link SharedSecretModel} object
	 * @return the new created shared {@link SecretKey} object from the given arguments
	 * @throws InvalidKeyException
	 *             if the private key is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the key agreement algorithm is not available
	 * @throws NoSuchProviderException
	 *             if the provider is not registered
	 */
	public static SecretKey newSharedSecret(SharedSecretModel sharedSecretModel)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyAgreement keyAgreement = newKeyAgreement(sharedSecretModel.getPrivateKey(),
			sharedSecretModel.getPublicKey(), sharedSecretModel.getKeyAgreementAlgorithm(),
			sharedSecretModel.getProvider(), true);
		byte[] sharedSecret = keyAgreement.generateSecret();
		return new SecretKeySpec(sharedSecret, 0, 16, sharedSecretModel.getKeyAgreementAlgorithm());
	}

	/**
	 * Factory method for creating a new shared {@link SecretKey} object from the given
	 * {@link SharedSecretInfo}.
	 *
	 * @param sharedSecretInfo
	 *            the {@link SharedSecretInfo} object
	 * @return the new created shared {@link SecretKey} object from the given arguments
	 * @throws InvalidKeyException
	 *             if the private key is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the key agreement algorithm is not available
	 * @throws NoSuchProviderException
	 *             if the provider is not registered
	 */
	public static SecretKey newSharedSecret(SharedSecretInfo sharedSecretInfo)
		throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException
	{
		SharedSecretModel sharedSecretModel = SharedSecretExtensions.toModel(sharedSecretInfo);
		return newSharedSecret(sharedSecretModel);
	}

	/**
	 * Factory method for creating a new shared {@link SecretKey} object from the given arguments.
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
	 * @return the new created shared {@link SecretKey} object from the given arguments
	 * @throws InvalidKeyException
	 *             if the private key is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the key agreement algorithm is not available
	 * @throws NoSuchProviderException
	 *             if the provider is not registered For instance:<br>
	 *             SecretKey secretKey = KeyAgreementFactory.newSharedSecret( privateKey, publicKey,
	 *             "ECDH", "AES", "SunJCE");
	 */
	public static SecretKey newSharedSecret(PrivateKey privateKey, PublicKey publicKey,
		String keyAgreementAlgorithm, String secretKeyAlgorithm, String provider)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyAgreement keyAgreement = newKeyAgreement(privateKey, publicKey, keyAgreementAlgorithm,
			provider, true);
		byte[] sharedSecret = keyAgreement.generateSecret();
		return new SecretKeySpec(sharedSecret, 0, 16, secretKeyAlgorithm);
	}

	/**
	 * Factory method for creating a new shared {@link SecretKey} object from the given arguments.
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
	 *            indicates whether this is the last phase of the key agreement
	 * @return the new created shared {@link SecretKey} object from the given arguments
	 * @throws InvalidKeyException
	 *             if the private key is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the key agreement algorithm is not available
	 * @throws NoSuchProviderException
	 *             if the provider is not registered For instance:<br>
	 *             SecretKey secretKey = KeyAgreementFactory.newSharedSecret( privateKey, publicKey,
	 *             "ECDH", "AES", "SunJCE", true);
	 */
	public static SecretKey newSharedSecret(PrivateKey privateKey, PublicKey publicKey,
		String keyAgreementAlgorithm, String secretKeyAlgorithm, String provider, boolean lastPhase)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyAgreement keyAgreement = newKeyAgreement(privateKey, publicKey, keyAgreementAlgorithm,
			provider, lastPhase);
		byte[] sharedSecret = keyAgreement.generateSecret();
		return new SecretKeySpec(sharedSecret, 0, 16, secretKeyAlgorithm);
	}

	/**
	 * Factory method for creating a new shared secret byte array from the given arguments.
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
	 *            indicates whether this is the last phase of the key agreement
	 * @return the new created shared secret byte array from the given arguments
	 * @throws InvalidKeyException
	 *             if the private key is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the key agreement algorithm is not available
	 * @throws NoSuchProviderException
	 *             if the provider is not registered For instance:<br>
	 *             byte[] sharedSecret = KeyAgreementFactory.newSharedSecret( privateKey, publicKey,
	 *             "ECDH", "SunJCE", true);
	 */
	public static byte[] newSharedSecret(PrivateKey privateKey, PublicKey publicKey,
		String keyAgreementAlgorithm, String provider, boolean lastPhase)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyAgreement keyAgreement = newKeyAgreement(privateKey, publicKey, keyAgreementAlgorithm,
			provider, lastPhase);
		return keyAgreement.generateSecret();
	}

	/**
	 * Factory method for creating a new shared secret byte array from the given arguments.
	 *
	 * @param privateKey
	 *            the private key
	 * @param publicKey
	 *            the public key
	 * @param keyAgreementAlgorithm
	 *            the key agreement algorithm
	 * @param provider
	 *            the provider
	 * @return the new created shared secret byte array from the given arguments
	 * @throws InvalidKeyException
	 *             if the private key is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the key agreement algorithm is not available
	 * @throws NoSuchProviderException
	 *             if the provider is not registered For instance:<br>
	 *             byte[] sharedSecret = KeyAgreementFactory.newSharedSecret( privateKey, publicKey,
	 *             "ECDH", "SunJCE");
	 */
	public static byte[] newSharedSecret(PrivateKey privateKey, PublicKey publicKey,
		String keyAgreementAlgorithm, String provider)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		return newSharedSecret(privateKey, publicKey, keyAgreementAlgorithm, provider, true);
	}

	/**
	 * Factory method for creating a new {@link KeyAgreement} object from the given arguments.
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
	 *            indicates whether this is the last phase of the key agreement
	 * @return the new created {@link KeyAgreement} object from the given arguments
	 * @throws InvalidKeyException
	 *             if the private key is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the key agreement algorithm is not available
	 * @throws NoSuchProviderException
	 *             if the provider is not registered For instance:<br>
	 *             KeyAgreement keyAgreement = KeyAgreementFactory.newKeyAgreement( privateKey,
	 *             publicKey, "ECDH", "SunJCE", true);
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
