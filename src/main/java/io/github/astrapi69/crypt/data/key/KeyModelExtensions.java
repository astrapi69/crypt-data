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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;

import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.crypt.data.model.KeyModel;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link KeyModelExtensions} provides algorithms for transform a given {@link KeyModel}
 * object to the appropriate key objects and given keys to the appropriate {@link KeyModel} object
 * 
 * @deprecated use instead the class {@link KeyInfoExtensions}. Note will be removed in next minor
 *             version
 */
@Deprecated
public class KeyModelExtensions
{

	/**
	 * Reads the given byte array with the given algorithm and returns the {@link PrivateKey}
	 * object.
	 *
	 * @param keyModel
	 *            the info model for create the private key
	 * @return the {@link PrivateKey} object
	 */
	public static PrivateKey toPrivateKey(KeyModel keyModel)
	{
		Objects.requireNonNull(keyModel);
		if (!keyModel.getKeyType().equals(KeyType.PRIVATE_KEY))
		{
			throw new RuntimeException(
				"Given KeyModel:" + keyModel.toString() + "\n is not a private key");
		}
		return RuntimeExceptionDecorator.decorate(
			() -> PrivateKeyReader.readPrivateKey(keyModel.getEncoded(), keyModel.getAlgorithm()));
	}


	/**
	 * Reads the given byte array with the given algorithm and returns the {@link PrivateKey}
	 * object.
	 *
	 * @param keyModel
	 *            the info model for create the private key
	 * @return the {@link PrivateKey} object
	 */
	public static PublicKey toPublicKey(KeyModel keyModel)
	{
		Objects.requireNonNull(keyModel);
		if (!keyModel.getKeyType().equals(KeyType.PUBLIC_KEY))
		{
			throw new RuntimeException(
				"Given KeyModel:" + keyModel.toString() + "\n is not a public key");
		}
		return RuntimeExceptionDecorator.decorate(
			() -> PublicKeyReader.readPublicKey(keyModel.getEncoded(), keyModel.getAlgorithm()));
	}

	/**
	 * Reads the given byte array with the given algorithm and returns the {@link PrivateKey}
	 * object.
	 *
	 * @param keyModel
	 *            the info model for create the private key
	 * @return the {@link PrivateKey} object
	 */
	public static X509Certificate toX509Certificate(KeyModel keyModel)
	{
		Objects.requireNonNull(keyModel);
		if (!keyModel.getKeyType().equals(KeyType.CERTIFICATE))
		{
			throw new RuntimeException(
				"Given KeyModel:" + keyModel.toString() + "\n is not a X509Certificate");
		}
		return RuntimeExceptionDecorator
			.decorate(() -> CertificateReader.readCertificate(keyModel.getEncoded()));
	}

	/**
	 * Transforms the given {@link PrivateKey} object to a {@link KeyModel} object
	 * 
	 * @param privateKey
	 *            the {@link PrivateKey} object to transform
	 * @return the {@link KeyModel} object from the given {@link PrivateKey} object
	 */
	public static KeyModel toKeyModel(PrivateKey privateKey)
	{
		return KeyModel.builder().encoded(privateKey.getEncoded()).keyType(KeyType.PRIVATE_KEY)
			.algorithm(privateKey.getAlgorithm()).build();
	}

	/**
	 * Transforms the given {@link PublicKey} object to a {@link KeyModel} object
	 * 
	 * @param publicKey
	 *            the {@link PublicKey} object to transform
	 * @return the {@link KeyModel} object from the given {@link PublicKey} object
	 */
	public static KeyModel toKeyModel(PublicKey publicKey)
	{
		return KeyModel.builder().encoded(publicKey.getEncoded()).keyType(KeyType.PUBLIC_KEY)
			.algorithm(publicKey.getAlgorithm()).build();
	}

	/**
	 * Transforms the given {@link Certificate} object to a {@link KeyModel} object
	 * 
	 * @param certificate
	 *            the {@link Certificate} object to transform
	 * @return the {@link KeyModel} object from the given {@link Certificate} object
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs
	 */
	public static KeyModel toKeyModel(Certificate certificate) throws CertificateEncodingException
	{
		return KeyModel.builder().encoded(CertificateExtensions.getEncoded(certificate))
			.keyType(KeyType.CERTIFICATE).build();
	}

}
