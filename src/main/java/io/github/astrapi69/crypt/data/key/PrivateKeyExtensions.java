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
import java.math.BigInteger;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import java.util.logging.Level;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.api.provider.SecurityProvider;
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
	 *             <p>
	 *             The header is always {@code RSA PRIVATE KEY}: this takes bytes and no key, so it
	 *             cannot tell which algorithm they belong to, and PKCS#1 names an RSA structure. An
	 *             EC or DSA key in its traditional form needs its own header - use
	 *             {@link #toPemFormat(PrivateKey)}, which picks the one that belongs to the key.
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
		Objects.requireNonNull(privateKey);
		if (privateKey instanceof RSAPrivateCrtKey rsaPrivateKey)
		{
			return KeyFactory.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm())
				.generatePublic(new RSAPublicKeySpec(rsaPrivateKey.getModulus(),
					rsaPrivateKey.getPublicExponent()));
		}
		if (privateKey instanceof DHPrivateKey diffieHellmanKey)
		{
			// bouncy castle's PrivateKeyFactory refuses a diffie-hellman key with "algorithm
			// identifier in private key not recognised", so this one is derived from the jca side.
			// The public value is g raised to x modulo p, which the key's own parameters carry
			DHParameterSpec parameters = diffieHellmanKey.getParams();
			BigInteger publicValue = parameters.getG().modPow(diffieHellmanKey.getX(),
				parameters.getP());
			return toDiffieHellmanPublicKey(privateKey, publicValue, parameters);
		}
		return fromKeyParameters(privateKey);
	}

	/**
	 * Derives the {@link PublicKey} object that belongs to the given {@link PrivateKey} object
	 * through the bouncy castle key parameters, which carry everything the public value is made of
	 *
	 * @param privateKey
	 *            the private key
	 * @return the corresponding {@link PublicKey} object
	 * @throws InvalidKeySpecException
	 *             is thrown if no public key can be derived from the given private key
	 */
	private static PublicKey fromKeyParameters(final PrivateKey privateKey)
		throws InvalidKeySpecException
	{
		try
		{
			AsymmetricKeyParameter privateKeyParameters = PrivateKeyFactory
				.createKey(privateKey.getEncoded());
			return new JcaPEMKeyConverter().setProvider(SecurityProvider.BC.name())
				.getPublicKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
					publicKeyParametersOf(privateKeyParameters, privateKey.getAlgorithm())));
		}
		catch (IOException | RuntimeException cannotBeDerived)
		{
			// bouncy castle refusing the bytes is the answer here: they are no private key
			// structure it knows, so there is nothing to derive from. An InvalidKeySpecException
			// out of publicKeyParametersOf is not caught here and keeps its own message
			throw new InvalidKeySpecException("No public key could be derived from the given '"
				+ privateKey.getAlgorithm() + "' private key: " + cannotBeDerived.getMessage(),
				cannotBeDerived);
		}
	}

	/**
	 * Builds the diffie-hellman {@link PublicKey} object from the given public value
	 * <p>
	 * The algorithm identifier is taken from the private key rather than rebuilt, because it
	 * carries q and the validation parameters that a {@link DHPublicKeySpec} has no room for and
	 * would silently drop. Bouncy castle's SubjectPublicKeyInfoFactory is no help here either: it
	 * answers "key parameters not recognized" for a diffie-hellman key, the mirror of its
	 * PrivateKeyFactory refusing to read one.
	 *
	 * @param privateKey
	 *            the private key whose algorithm identifier is reused
	 * @param publicValue
	 *            the public value, g raised to x modulo p
	 * @param parameters
	 *            the parameters of the private key, used when its encoding cannot be read
	 * @return the {@link PublicKey} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the KeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if no key can be built from what was assembled
	 */
	private static PublicKey toDiffieHellmanPublicKey(final PrivateKey privateKey,
		final BigInteger publicValue, final DHParameterSpec parameters)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		KeyFactory keyFactory = KeyFactory
			.getInstance(KeyPairGeneratorAlgorithm.DIFFIE_HELLMAN.getAlgorithm());
		try
		{
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
			byte[] encoded = new SubjectPublicKeyInfo(privateKeyInfo.getPrivateKeyAlgorithm(),
				new ASN1Integer(publicValue)).getEncoded();
			return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
		}
		catch (IOException | RuntimeException noAlgorithmIdentifierToReuse)
		{
			// no readable identifier to carry over, so the plain parameters are all there is
			return keyFactory.generatePublic(
				new DHPublicKeySpec(publicValue, parameters.getP(), parameters.getG()));
		}
	}


	/**
	 * Derives the public key parameters that belong to the given private key parameters
	 *
	 * @param privateKeyParameters
	 *            the private key parameters
	 * @param algorithm
	 *            the algorithm of the private key, for the failure message
	 * @return the corresponding public key parameters
	 * @throws InvalidKeySpecException
	 *             is thrown if the given private key parameters are of no known kind
	 */
	private static AsymmetricKeyParameter publicKeyParametersOf(
		final AsymmetricKeyParameter privateKeyParameters, final String algorithm)
		throws InvalidKeySpecException
	{
		if (privateKeyParameters instanceof Ed25519PrivateKeyParameters edwardsKey)
		{
			return edwardsKey.generatePublicKey();
		}
		if (privateKeyParameters instanceof Ed448PrivateKeyParameters edwardsKey)
		{
			return edwardsKey.generatePublicKey();
		}
		if (privateKeyParameters instanceof X25519PrivateKeyParameters montgomeryKey)
		{
			return montgomeryKey.generatePublicKey();
		}
		if (privateKeyParameters instanceof X448PrivateKeyParameters montgomeryKey)
		{
			return montgomeryKey.generatePublicKey();
		}
		if (privateKeyParameters instanceof ECPrivateKeyParameters ecKey)
		{
			// the public point is the generator multiplied by the private value, on the key's own
			// curve. The multiplier is bouncy castle's, not arithmetic written here
			return new ECPublicKeyParameters(
				new FixedPointCombMultiplier().multiply(ecKey.getParameters().getG(), ecKey.getD()),
				ecKey.getParameters());
		}
		if (privateKeyParameters instanceof DSAPrivateKeyParameters dsaKey)
		{
			return new DSAPublicKeyParameters(
				dsaKey.getParameters().getG().modPow(dsaKey.getX(), dsaKey.getParameters().getP()),
				dsaKey.getParameters());
		}
		if (privateKeyParameters instanceof MLDSAPrivateKeyParameters postQuantumKey)
		{
			return postQuantumKey.getPublicKeyParameters();
		}
		if (privateKeyParameters instanceof MLKEMPrivateKeyParameters postQuantumKey)
		{
			return postQuantumKey.getPublicKeyParameters();
		}
		// no rsa branch here: an rsa key never reaches this method, it is served from its own jca
		// interface before the bouncy castle parameters are asked for at all
		//
		// slh-dsa is missing on purpose: its private key parameters hand out the public key as
		// bytes, and SLHDSAPublicKeyParameters has no public constructor to make an object of them
		throw new InvalidKeySpecException("No public key can be derived from a '" + algorithm
			+ "' private key, whose parameters are a " + privateKeyParameters.getClass().getName()
			+ ". Derivable are RSA, DSA, EC, Ed25519, Ed448, X25519, X448, ML-DSA, ML-KEM and "
			+ "DiffieHellman keys");
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
	 * Transform the given private key to a {@link String} object in pem format, in the traditional
	 * form of its algorithm: {@code RSA PRIVATE KEY}, {@code EC PRIVATE KEY} or
	 * {@code DSA PRIVATE KEY} over the PKCS#1 content, each under the header that names it.
	 * <p>
	 * An algorithm with no traditional form of its own keeps its PKCS#8 encoding, under the
	 * {@code PRIVATE KEY} header - see {@link #toPkcs8PemFormat(PrivateKey)}. Writing stripped
	 * content under that header would claim a format the bytes are not in.
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
		else if (privateKey instanceof RSAPrivateKey)
		{
			return PemObjectReader.toPemFormat(
				new PemObject(PemType.RSA_PRIVATE_KEY.getName(), toPKCS1Format(privateKey)));
		}
		// A key with no traditional form of its own - Ed25519, Ed448, the post-quantum families -
		// has nothing to strip the wrapper for. Writing it under the PRIVATE KEY header, which
		// means PKCS#8, over PKCS#1 content produced a file that was readable as neither format
		// (issue #12), so it keeps its PKCS#8 encoding here.
		return toPkcs8PemFormat(privateKey);
	}

	/**
	 * Transform the given private key to a {@link String} object in pem format, in PKCS#8 - the
	 * encoding {@link PrivateKey#getEncoded()} returns, under the {@code PRIVATE KEY} header that
	 * names it.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link String} object in pem format generated from the given private key
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static String toPkcs8PemFormat(final PrivateKey privateKey) throws IOException
	{
		return PemObjectReader
			.toPemFormat(new PemObject(PemType.PRIVATE_KEY.getName(), privateKey.getEncoded()));
	}

	/**
	 * Transform the given private key to the traditional format of its own algorithm and returns it
	 * as a byte array
	 * <p>
	 * PKCS#1 is the traditional format of an RSA key; an EC key has RFC 5915 and a DSA key has the
	 * structure OpenSSL writes under the DSA PRIVATE KEY header. For the first two that is the
	 * PKCS#8 wrapper taken off, which is what this used to do for every key.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the byte array in the traditional format of the key's algorithm
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static byte[] toPKCS1Format(final PrivateKey privateKey) throws IOException
	{
		if (privateKey instanceof DSAPrivateKey)
		{
			// a dsa key is a number in a group, and the group - p, q and g - lives in the
			// algorithm identifier of the pkcs#8 wrapper. Taking the wrapper off therefore left
			// the private exponent alone, a number no reader could make a key out of again
			// (issue #15). Bouncy castle assembles the structure that carries the group with it
			return new JcaMiscPEMGenerator(privateKey).generate().getContent();
		}
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
