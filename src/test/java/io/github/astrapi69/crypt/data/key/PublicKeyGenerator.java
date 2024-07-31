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

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.astrapi69.crypt.data.key.writer.PublicKeyWriter;

public class PublicKeyGenerator
{

	public static void main(String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		generateAndSaveKeyPair("RSA", 2048, "public_rsa.pem");
		generateAndSaveKeyPair("DSA", 1024, "public_dsa.pem");
		generateAndSaveKeyPair("EC", 256, "public_ec.pem");
	}

	private static void generateAndSaveKeyPair(String algorithm, int keySize, String fileName)
		throws NoSuchAlgorithmException, NoSuchProviderException, IOException
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(keySize);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		File file = new File("src/test/resources/pem/" + fileName);
		PublicKey aPublic = keyPair.getPublic();
		PublicKeyWriter.writeInPemFormat(aPublic, file);
	}

}
