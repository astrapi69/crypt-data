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
package io.github.astrapi69.crypt.data.key.reader;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.key.writer.EncryptedPrivateKeyWriter;

public class TestPrivateKeyGenerator
{

	public static void main(String[] args)
	{
		try
		{
			generateAndSaveEncryptedPrivateKey(KeyPairGeneratorAlgorithm.RSA.getAlgorithm(),
				"secret", "src/test/resources/der/test-key-rsa.der", 2048);
			generateAndSaveEncryptedPrivateKey(KeyPairGeneratorAlgorithm.DSA.getAlgorithm(),
				"password123", "src/test/resources/der/test-key-dsa.der", 2048);
			generateAndSaveEncryptedPrivateKey(KeyPairGeneratorAlgorithm.EC.getAlgorithm(),
				"myPassword", "src/test/resources/der/test-key-ec.der", 256);
			generateAndSaveEncryptedPrivateKey(KeyPairGeneratorAlgorithm.DH.getAlgorithm(),
				"dhPassword", "src/test/resources/der/test-key-dh.der", 2048);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * Generates an encrypted private key and saves it to a file.
	 *
	 * @param algorithm
	 *            the algorithm to generate the key pair
	 * @param password
	 *            the password to encrypt the private key
	 * @param filePath
	 *            the file path to save the encrypted private key
	 * @param keySize
	 *            the size of the key
	 * @throws NoSuchAlgorithmException,
	 *             InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
	 *             InvalidAlgorithmParameterException, IllegalBlockSizeException,
	 *             BadPaddingException, IOException, InvalidParameterSpecException
	 */
	public static void generateAndSaveEncryptedPrivateKey(String algorithm, String password,
		String filePath, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
		IllegalBlockSizeException, BadPaddingException, IOException, InvalidParameterSpecException
	{

		// Generate key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);

		if ("EC".equalsIgnoreCase(algorithm))
		{
			keyGen.initialize(new ECGenParameterSpec("secp256r1"));
		}
		else
		{
			keyGen.initialize(keySize);
		}

		KeyPair keyPair = keyGen.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();

		// Encrypt the private key with the password and save it to a file
		File file = new File(filePath);
		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(privateKey, file, password);
	}
}
