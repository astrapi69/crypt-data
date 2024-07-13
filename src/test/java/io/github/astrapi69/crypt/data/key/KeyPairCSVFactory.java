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

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class KeyPairCSVFactory
{

	public static void generateCSVFiles(String directory)
		throws NoSuchAlgorithmException, IOException, InvalidKeySpecException
	{
		generatePrivateKeyCSV(directory + "/private_key_data.csv");
		generatePublicKeyCSV(directory + "/public_key_data.csv");
		// generation of
		// generateCertificateCSV(directory + "/certificate_data.csv");
	}

	private static void generatePrivateKeyCSV(String filePath)
		throws NoSuchAlgorithmException, IOException
	{
		FileWriter writer = new FileWriter(filePath);
		writer.append("keyType,encoded,algorithm\n");
		writer.append(generateKeyPairEntry("RSA", 2048));
		writer.append(generateKeyPairEntry("EC", 256));
		writer.flush();
		writer.close();
	}

	private static void generatePublicKeyCSV(String filePath)
		throws NoSuchAlgorithmException, IOException
	{
		FileWriter writer = new FileWriter(filePath);
		writer.append("keyType,encoded,algorithm\n");
		writer.append(generatePublicKeyEntry("RSA", 2048));
		writer.append(generatePublicKeyEntry("EC", 256));
		writer.flush();
		writer.close();
	}

	private static void generateCertificateCSV(String filePath)
		throws NoSuchAlgorithmException, IOException
	{
		// This method is a placeholder since certificate generation is more complex and usually
		// requires a CA
		// For this example, we'll use the public keys and pretend they're certificates
		FileWriter writer = new FileWriter(filePath);
		writer.append("keyType,encoded,algorithm\n");
		writer.append(generatePublicKeyEntry("RSA", 2048));
		writer.append(generatePublicKeyEntry("EC", 256));
		writer.flush();
		writer.close();
	}

	private static String generateKeyPairEntry(String algorithm, int keySize)
		throws NoSuchAlgorithmException
	{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
		keyGen.initialize(keySize);
		KeyPair keyPair = keyGen.generateKeyPair();
		String privateKeyEncoded = Base64.getEncoder()
			.encodeToString(keyPair.getPrivate().getEncoded());
		return String.format("Private key,%s,%s\n", privateKeyEncoded, algorithm);
	}

	private static String generatePublicKeyEntry(String algorithm, int keySize)
		throws NoSuchAlgorithmException
	{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
		keyGen.initialize(keySize);
		KeyPair keyPair = keyGen.generateKeyPair();
		String publicKeyEncoded = Base64.getEncoder()
			.encodeToString(keyPair.getPublic().getEncoded());
		return String.format("Public key,%s,%s\n", publicKeyEncoded, algorithm);
	}

	public static void main(String[] args)
	{
		try
		{
			Files.createDirectories(Paths.get("csv_output"));
			generateCSVFiles("csv_output");
			System.out.println("CSV files generated successfully.");
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}
}
