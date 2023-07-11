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
package io.github.astrapi69.crypt.data.example.keyagreement;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.factory.KeyPairGeneratorFactory;
import io.github.astrapi69.crypt.data.factory.KeySpecFactory;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;

/**
 * The unit test for an example for KeyAgreement communication
 */
public class KeyAgreementTest
{
	/**
	 * Test method for KeyAgreement communication
	 */
	@Test
	void newSharedSecret() throws Exception
	{
		String cipherAlgorithm;
		String secretKeyAlgorithm;
		String keyAgreementAlgorithm;
		String keyFactoryAlgorithm;
		String keyPairGeneratorAlgorithm;
		KeyPairGenerator keyPairGenerator;
		int keySize;

		// 1. The initiator(Alice in our case) generates a key pair(public and private) and sends
		// the public key, along with the algorithm specification, to the other(Bob in our case)
		// party.
		keyPairGeneratorAlgorithm = "EC";
		keyFactoryAlgorithm = keyPairGeneratorAlgorithm;
		secretKeyAlgorithm = "DES";
		keyAgreementAlgorithm = "ECDH";
		cipherAlgorithm = "DES/ECB/PKCS5Padding";
		keySize = 256;
		keyPairGenerator = KeyPairGeneratorFactory.newKeyPairGenerator(keyPairGeneratorAlgorithm);
		keyPairGenerator.initialize(keySize);

		KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();
		byte[] alicePk = aliceKeyPair.getPublic().getEncoded();

		// Display public key from Alice
		System.out.format("Alice Public Key: %s%n", printHexBinary(alicePk));

		// 2. The other(Bob in our case) party generates its own key pair(public and private) using
		// the algorithm specification and sends the public key to the initiator(Alice in our case).

		keyPairGenerator = KeyPairGeneratorFactory.newKeyPairGenerator(keyPairGeneratorAlgorithm);
		keyPairGenerator.initialize(keySize);
		KeyPair bobKeyPair = keyPairGenerator.generateKeyPair();

		byte[] bobPk = bobKeyPair.getPublic().getEncoded();
		// Display public key from Bob
		System.out.format("Bob Public Key: %s%n", printHexBinary(bobPk));

		KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm);
		X509EncodedKeySpec bobPkSpec = new X509EncodedKeySpec(bobPk);
		PublicKey bobPublicKey = keyFactory.generatePublic(bobPkSpec);
		// 3. The initiator(Alice in our case) generates the secret key using its private key and
		// the other(Bob in our case) party's public key.
		// Create key agreement
		KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance(keyAgreementAlgorithm);
		aliceKeyAgreement.init(aliceKeyPair.getPrivate());
		aliceKeyAgreement.doPhase(bobPublicKey, true);

		// Read shared secret from Alice
		byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();
		System.out.format("Alice Shared secret: %s%n", printHexBinary(aliceSharedSecret));

		// 4. The other party also generates the secret key using its private key and the
		// initiator's public key. Diffie-Hellamn algorithm ensures that both parties generate the
		// same secret key.
		// Create key agreement for Bob
		KeyAgreement bobKeyAgreement = KeyAgreement.getInstance(keyAgreementAlgorithm);
		bobKeyAgreement.init(bobKeyPair.getPrivate());
		bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);

		// Read shared secret from Bob
		byte[] bobSharedSecret = aliceKeyAgreement.generateSecret();
		System.out.format("Bob Shared secret: %s%n", printHexBinary(bobSharedSecret));

		// 5. generate key from Alice shared secret
		SecretKey aliceSecretKey = SecretKeyFactoryExtensions.newSecretKey(aliceSharedSecret,
			secretKeyAlgorithm);

		Cipher aliceCipher = Cipher.getInstance(cipherAlgorithm);
		aliceCipher.init(Cipher.ENCRYPT_MODE, aliceSecretKey);
		byte[] encryptedByteArray = aliceCipher
			.doFinal("Free your mind and get the best out of you".getBytes());

		// Step 6: generate key from Bob shared secret
		SecretKeyFactory bobSecretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
		DESKeySpec bobKeySpec = new DESKeySpec(bobSharedSecret);
		SecretKey bobSecretKey = bobSecretKeyFactory.generateSecret(bobKeySpec);

		// Step 8: Bob receives the encrypted text and decrypts it
		Cipher bobCipher = Cipher.getInstance(cipherAlgorithm);
		bobCipher.init(Cipher.DECRYPT_MODE, bobSecretKey);
		byte[] plaintext = bobCipher.doFinal(encryptedByteArray);
		String text = new String(plaintext);
		System.out.println("Bob reads the message of Alice:\n" + text);
	}


	public static SecretKey newSecretKey(byte[] sharedSecret, String secretKeyAlgorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
		SecretKeySpec secretKeySpec = KeySpecFactory.newSecretKeySpec(sharedSecret,
			secretKeyAlgorithm);
		SecretKey secretKey = secretKeyFactory.generateSecret(secretKeySpec);
		return secretKey;
	}
}
