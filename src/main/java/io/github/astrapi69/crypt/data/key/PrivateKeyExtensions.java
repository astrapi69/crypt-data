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

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.hex.HexExtensions;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;
import lombok.extern.java.Log;

/**
 * The class {@link PrivateKeyExtensions} provides utility methods for working with
 * {@link PrivateKey} objects
 */
@Log
public final class PrivateKeyExtensions
{

	private PrivateKeyExtensions()
	{
	}

	/**
	 * Transform the given byte array (of private key in PKCS#1 format) to a PEM formatted
	 * {@link String}
	 *
	 * @param privateKeyPKCS1Formatted
	 *            the byte array (of private key in PKCS#1 format)
	 * @return the String in PEM format
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static String fromPKCS1ToPemFormat(final byte[] privateKeyPKCS1Formatted)
		throws IOException
	{
		PemObject pemObject = new PemObject(PemType.RSA_PRIVATE_KEY.getName(),
			privateKeyPKCS1Formatted);
		StringWriter stringWriter = new StringWriter();
		PemWriter pemWriter = new PemWriter(stringWriter);
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		return stringWriter.toString();
	}

	/**
	 * Generate the corresponding {@link PublicKey} object from the given {@link PrivateKey} object
	 *
	 * @param privateKey
	 *            the private key
	 * @return the corresponding {@link PublicKey} object or null if generation failed
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 */
	public static PublicKey generatePublicKey(final PrivateKey privateKey)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		if (privateKey instanceof RSAPrivateKey)
		{
			final RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privateKey;
			final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privk.getModulus(),
				privk.getPublicExponent());

			final KeyFactory keyFactory = KeyFactory
				.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
			return keyFactory.generatePublic(publicKeySpec);
		}
		return null;
	}

	/**
	 * Gets the key length of the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            the private key
	 * @return the key length
	 */
	public static int getKeyLength(final PrivateKey privateKey)
	{
		int length = -1;
		if (privateKey == null)
		{
			return length;
		}
		if (privateKey instanceof RSAPrivateKey)
		{
			length = ((RSAPrivateKey)privateKey).getModulus().bitLength();
		}
		else if (privateKey instanceof DSAPrivateKey)
		{
			length = ((DSAPrivateKey)privateKey).getParams().getQ().bitLength();
		}
		else if (privateKey instanceof ECPrivateKey)
		{
			length = ((ECPrivateKey)privateKey).getParams().getCurve().getField().getFieldSize();
		}
		return length;
	}

	/**
	 * Gets the {@link KeySize} of the given {@link PrivateKey} or null if not found
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link KeySize} of the given {@link PrivateKey} or null if not found
	 */
	public static KeySize getKeySize(final PrivateKey privateKey)
	{
		int length = getKeyLength(privateKey);
		if (length == 1024)
		{
			return KeySize.KEYSIZE_1024;
		}
		else if (length == 2048)
		{
			return KeySize.KEYSIZE_2048;
		}
		else if (length == 4096)
		{
			return KeySize.KEYSIZE_4096;
		}
		else if (length == 8192)
		{
			return KeySize.KEYSIZE_8192;
		}
		return KeySize.UNKNOWN;
	}

	/**
	 * Transform the given {@link PrivateKey} to a base64 encoded {@link String} value
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new base64 encoded {@link String} value
	 */
	public static String toBase64(final PrivateKey privateKey)
	{
		return KeyExtensions.toBase64(privateKey.getEncoded());
	}

	/**
	 * Transform the given {@link PrivateKey} to a base64 encoded {@link String} value
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new base64 encoded {@link String} value
	 */
	public static String toBase64Binary(final PrivateKey privateKey)
	{
		return KeyExtensions.toBase64Binary(privateKey.getEncoded());
	}

	/**
	 * Transform the given {@link PrivateKey} to a hexadecimal {@link String} value
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new hexadecimal {@link String} value
	 */
	public static String toHexString(final PrivateKey privateKey)
	{
		return toHexString(privateKey, true);
	}

	/**
	 * Transform the given {@link PrivateKey} to a hexadecimal {@link String} value
	 *
	 * @param privateKey
	 *            the private key
	 * @param lowerCase
	 *            the flag if the result shall be transformed in lower case
	 * @return the new hexadecimal {@link String} value
	 */
	public static String toHexString(final PrivateKey privateKey, final boolean lowerCase)
	{
		return HexExtensions.toHexString(privateKey.getEncoded(), lowerCase);
	}

	/**
	 * Transform the given private key that is in PKCS1 format and returns a {@link String} object
	 * in pem format
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link String} object in pem format generated from the given private key
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static String toPemFormat(final PrivateKey privateKey) throws IOException
	{
		if (privateKey instanceof ECPrivateKey)
		{
			return PemObjectReader.toPemFormat(
				new PemObject(PemType.EC_PRIVATE_KEY.getName(), toPKCS1Format(privateKey)));
		}
		else if (privateKey instanceof DSAPrivateKey)
		{
			return PemObjectReader.toPemFormat(
				new PemObject(PemType.DSA_PRIVATE_KEY.getName(), toPKCS1Format(privateKey)));
		}
		return PemObjectReader.toPemFormat(
			new PemObject(PemType.RSA_PRIVATE_KEY.getName(), toPKCS1Format(privateKey)));
	}

	/**
	 * Transform the given private key to PKCS#1 format and returns it as a byte array
	 *
	 * @param privateKey
	 *            the private key
	 * @return the byte array formatted in PKCS#1
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static byte[] toPKCS1Format(final PrivateKey privateKey) throws IOException
	{
		final byte[] encoded = privateKey.getEncoded();
		final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encoded);
		final ASN1Encodable asn1Encodable = privateKeyInfo.parsePrivateKey();
		final ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
		return asn1Primitive.getEncoded();
	}

	/**
	 * Get the standard algorithm name from the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            the private key
	 * @return the standard algorithm name from the given {@link PrivateKey}
	 */
	public static String getAlgorithm(final PrivateKey privateKey)
	{
		return privateKey.getAlgorithm();
	}

	/**
	 * Get the name of the primary encoding format from the given {@link PrivateKey} or null if it
	 * does not support encoding
	 *
	 * @param privateKey
	 *            the private key
	 * @return the name of the primary encoding format from the given {@link PrivateKey} or null if
	 *         it does not support encoding
	 */
	public static String getFormat(final PrivateKey privateKey)
	{
		return privateKey.getFormat();
	}

	/**
	 * Get the {@link PrivateKey} in its primary encoding format, or null if this key does not
	 * support encoding
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link PrivateKey} in its primary encoding format, or null if this key does not
	 *         support encoding
	 */
	public static byte[] getEncoded(final PrivateKey privateKey)
	{
		return privateKey.getEncoded();
	}

	/**
	 * Parses the private key bytes to determine the algorithm used
	 *
	 * @param keyBytes
	 *            the byte array containing the private key
	 * @return the name of the algorithm, or "Unknown" if the algorithm could not be determined
	 */
	public static String getAlgorithm(byte[] keyBytes)
	{
		try
		{
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(keyBytes);
			ASN1ObjectIdentifier algorithmOID = privateKeyInfo.getPrivateKeyAlgorithm()
				.getAlgorithm();
			return mapOidToAlgorithm(algorithmOID);
		}
		catch (Exception e)
		{
			log.log(Level.WARNING, "Algorithm from given key bytes can not be resolved", e);
			return "Unknown";
		}
	}

	/**
	 * Maps an ASN1ObjectIdentifier to the corresponding algorithm name
	 *
	 * @param oid
	 *            the ASN1ObjectIdentifier of the algorithm
	 * @return the name of the algorithm, or "Unknown" if the OID is not recognized
	 */
	private static String mapOidToAlgorithm(ASN1ObjectIdentifier oid)
	{
		if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1")))
		{
			return "RSA";
		}
		else if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10040.4.1")))
		{
			return "DSA";
		}
		else if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.2.1")))
		{
			return "EC";
		}
		else if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.3.1")))
		{
			return "DH";
		}
		else if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5")))
		{
			return "X.509";
		}
		else if (oid.equals(new ASN1ObjectIdentifier("1.3.101.112")))
		{
			return "EdDSA";
		}
		return "Unknown";
	}
}
