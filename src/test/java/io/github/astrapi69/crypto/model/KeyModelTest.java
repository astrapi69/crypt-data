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
package io.github.astrapi69.crypto.model;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypto.compound.CompoundAlgorithm;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.evaluate.object.evaluators.EqualsHashCodeAndToStringEvaluator;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.object.RandomStringFactory;

public class KeyModelTest
{
	File derDir;
	File pemDir;

	PrivateKey privateKey;

	File privateKeyDerFile;
	File privateKeyPemFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privateKeyPemFile = new File(pemDir, "private.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);
	}

	/**
	 * Test method for {@link KeyModel} constructors and builders
	 */
	@Test
	public final void testConstructors() throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		KeyModel keyModel = KeyModel.builder().encoded(privateKey.getEncoded())
			.algorithm(privateKey.getAlgorithm()).build();

		PrivateKey privateKeyFromModel = PrivateKeyReader.readPrivateKey(keyModel.getEncoded(),
			keyModel.getAlgorithm());

		assertEquals(privateKey, privateKeyFromModel);
	}

	/**
	 * Test method for {@link CryptModel#equals(Object)} , {@link CryptModel#hashCode()} and
	 * {@link CryptModel#toString()}
	 */
	@Test
	public void testEqualsHashcodeAndToStringWithClass()
		throws NoSuchMethodException, IllegalAccessException, InstantiationException,
		NoSuchFieldException, ClassNotFoundException, InvocationTargetException, IOException
	{
		boolean expected;
		boolean actual;

		actual = EqualsHashCodeAndToStringEvaluator
			.evaluateEqualsHashcodeAndToString(CryptModel.class, clazz -> {
				return CryptModel.<Cipher, String, String> builder()
					.key(RandomStringFactory.randomHexString(16).toUpperCase())
					.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(CompoundAlgorithm.SALT)
					.iterationCount(19).operationMode(Cipher.ENCRYPT_MODE)
					.decorator(
						CryptObjectDecorator.<String> builder().prefix("s").suffix("s").build())
					.build();
			});
		expected = true;
		assertEquals(expected, actual);
	}
}
