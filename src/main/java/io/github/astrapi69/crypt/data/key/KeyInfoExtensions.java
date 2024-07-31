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
import io.github.astrapi69.crypt.data.model.KeyInfo;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link KeyInfoExtensions} provides algorithms for transforming a given {@link KeyInfo}
 * object to the appropriate key objects and given keys to the appropriate {@link KeyInfo} object
 */
public class KeyInfoExtensions
{

	/**
	 * Reads the given byte array with the given algorithm and returns the {@link PrivateKey} object
	 *
	 * @param keyInfo
	 *            the info model for creating the private key
	 * @return the {@link PrivateKey} object
	 */
	public static PrivateKey toPrivateKey(KeyInfo keyInfo)
	{
		Objects.requireNonNull(keyInfo);
		KeyType keyType = KeyType.toKeyType(keyInfo.getKeyType());
		if (!keyType.equals(KeyType.PRIVATE_KEY))
		{
			throw new RuntimeException(
				"Given KeyInfo:" + keyInfo.toString() + "\n is not a private key");
		}
		return RuntimeExceptionDecorator.decorate(
			() -> PrivateKeyReader.readPrivateKey(keyInfo.getEncoded(), keyInfo.getAlgorithm()));
	}

	/**
	 * Reads the given byte array with the given algorithm and returns the {@link PublicKey} object
	 *
	 * @param keyInfo
	 *            the info model for creating the public key
	 * @return the {@link PublicKey} object
	 */
	public static PublicKey toPublicKey(KeyInfo keyInfo)
	{
		Objects.requireNonNull(keyInfo);
		KeyType keyType = KeyType.toKeyType(keyInfo.getKeyType());
		if (!keyType.equals(KeyType.PUBLIC_KEY))
		{
			throw new RuntimeException(
				"Given KeyInfo:" + keyInfo.toString() + "\n is not a public key");
		}
		return RuntimeExceptionDecorator.decorate(
			() -> PublicKeyReader.readPublicKey(keyInfo.getEncoded(), keyInfo.getAlgorithm()));
	}

	/**
	 * Reads the given byte array with the given algorithm and returns the {@link X509Certificate}
	 * object
	 *
	 * @param keyInfo
	 *            the info model for creating the X509 certificate
	 * @return the {@link X509Certificate} object
	 */
	public static X509Certificate toX509Certificate(KeyInfo keyInfo)
	{
		Objects.requireNonNull(keyInfo);
		if (!KeyType.toKeyType(keyInfo.getKeyType()).equals(KeyType.CERTIFICATE))
		{
			throw new RuntimeException(
				"Given KeyInfo:" + keyInfo.toString() + "\n is not a X509Certificate");
		}
		return RuntimeExceptionDecorator
			.decorate(() -> CertificateReader.readCertificate(keyInfo.getEncoded()));
	}

	/**
	 * Transforms the given {@link PrivateKey} object to a {@link KeyInfo} object
	 *
	 * @param privateKey
	 *            the {@link PrivateKey} object to transform
	 * @return the {@link KeyInfo} object from the given {@link PrivateKey} object
	 */
	public static KeyInfo toKeyInfo(PrivateKey privateKey)
	{
		return KeyInfo.builder().encoded(privateKey.getEncoded())
			.keyType(KeyType.PRIVATE_KEY.getDisplayValue()).algorithm(privateKey.getAlgorithm())
			.build();
	}

	/**
	 * Transforms the given {@link PublicKey} object to a {@link KeyInfo} object
	 *
	 * @param publicKey
	 *            the {@link PublicKey} object to transform
	 * @return the {@link KeyInfo} object from the given {@link PublicKey} object
	 */
	public static KeyInfo toKeyInfo(PublicKey publicKey)
	{
		return KeyInfo.builder().encoded(publicKey.getEncoded())
			.keyType(KeyType.PUBLIC_KEY.getDisplayValue()).algorithm(publicKey.getAlgorithm())
			.build();
	}

	/**
	 * Transforms the given {@link Certificate} object to a {@link KeyInfo} object
	 *
	 * @param certificate
	 *            the {@link Certificate} object to transform
	 * @return the {@link KeyInfo} object from the given {@link Certificate} object
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs
	 */
	public static KeyInfo toKeyInfo(X509Certificate certificate) throws CertificateEncodingException
	{
		byte[] encoded = CertificateExtensions.getEncoded(certificate);
		return KeyInfo.builder().encoded(encoded).algorithm(certificate.getSigAlgName())
			.keyType(KeyType.CERTIFICATE.getDisplayValue()).build();
	}

}
