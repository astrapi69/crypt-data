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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;


/**
 * The unit test class for the class {@link EncryptedPrivateKeyReader}
 */
public class EncryptedPrivateKeyReaderParameterizedTest
{

	/**
	 * Parameterized test method for
	 * {@link EncryptedPrivateKeyReader#readPasswordProtectedPrivateKey(File, String, String)}
	 *
	 * @param filePath
	 *            the file path to the password protected private key file
	 * @param password
	 *            the password to decrypt the private key
	 * @param algorithm
	 *            the algorithm of the private key
	 * @throws InvalidAlgorithmParameterException,
	 *             NoSuchPaddingException, IOException, NoSuchAlgorithmException,
	 *             InvalidKeySpecException, InvalidKeyException
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/encrypted-private-key-parameters.csv", numLinesToSkip = 1)
	public void parameterizedTestReadPasswordProtectedPrivateKeyFileStringString(String filePath,
		String password, String algorithm) throws InvalidAlgorithmParameterException,
		NoSuchPaddingException, IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		InvalidKeyException, OperatorCreationException, PKCSException
	{
		File file = new File(filePath);
		PrivateKey privateKey = EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(file,
			password, algorithm);
		assertNotNull(privateKey);
	}
}
