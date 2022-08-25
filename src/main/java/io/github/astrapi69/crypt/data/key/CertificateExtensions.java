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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import io.github.astrapi69.crypt.data.hex.HexExtensions;
import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;

/**
 * The class {@link CertificateExtensions} provides extension methods for {@link X509Certificate}
 * objects.
 */
public final class CertificateExtensions
{

	private CertificateExtensions()
	{
		throw new UnsupportedOperationException(
			"This is a utility class and cannot be instantiated");
	}

	/**
	 * Transforms the given {@link X509Certificate} object to a hexadecimal {@link String} object
	 *
	 * @param certificate
	 *            the certificate
	 * @return the hexadecimal {@link String} object from the given {@link X509Certificate} object
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs
	 */
	public static String toHex(final X509Certificate certificate)
		throws CertificateEncodingException
	{
		String base64 = KeyExtensions.toBase64(certificate.getEncoded());
		byte[] decoded = KeyExtensions.decodeBase64(base64);
		return Hex.encodeHexString(decoded);
	}

	/**
	 * Get the {@link X509Certificate} in its primary encoding format
	 *
	 * @param certificate
	 *            the certificate
	 * @return the {@link X509Certificate} in its primary encoding format
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs
	 */
	public static byte[] getEncoded(final X509Certificate certificate)
		throws CertificateEncodingException
	{
		return certificate.getEncoded();
	}

	/**
	 * Transforms the given {@link X509Certificate} object to a base64 {@link String} object
	 *
	 * @param certificate
	 *            the certificate
	 * @return the base64 {@link String} object from the given {@link X509Certificate} object
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs
	 */
	public static String toBase64(final X509Certificate certificate)
		throws CertificateEncodingException
	{
		return KeyExtensions.toBase64(getEncoded(certificate));
	}

	/**
	 * Gets the country value of the given {@link X509Certificate}.
	 *
	 * @param certificate
	 *            the certificate
	 * @return the country
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static String getCountry(final X509Certificate certificate)
		throws CertificateEncodingException
	{
		return getFirstValueOf(certificate, BCStyle.C);
	}

	/**
	 * Gets the fingerprint from the given {@link X509Certificate} and the given algorithm.
	 *
	 * @param certificate
	 *            the certificate
	 * @param hashAlgorithm
	 *            the hash algorithm
	 * @return the fingerprint
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	public static String getFingerprint(final X509Certificate certificate,
		final HashAlgorithm hashAlgorithm)
		throws CertificateEncodingException, NoSuchAlgorithmException
	{
		final byte[] derEncoded = certificate.getEncoded();
		final MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.getAlgorithm());
		messageDigest.update(derEncoded);
		final byte[] digest = messageDigest.digest();
		final String fingerprint = HexExtensions.toHexString(digest);
		return fingerprint;
	}

	/**
	 * Gets the first value of the given {@link X509Certificate} and the given
	 * {@link ASN1ObjectIdentifier}.
	 *
	 * @param certificate
	 *            the certificate
	 * @param style
	 *            the style
	 * @return the first value of the given {@link X509Certificate} and the given
	 *         {@link ASN1ObjectIdentifier} or an empty String if the {@link ASN1ObjectIdentifier}
	 *         does not exists.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static String getFirstValueOf(final X509Certificate certificate,
		final ASN1ObjectIdentifier style) throws CertificateEncodingException
	{
		final X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
		final RDN[] rdns = x500name.getRDNs(style);
		if (rdns != null && 0 < rdns.length)
		{
			final RDN rdn = rdns[0];
			final String firstValue = IETFUtils.valueToString(rdn.getFirst().getValue());
			return firstValue;
		}
		return "";
	}

	/**
	 * Gets the issued by value of the given {@link X509Certificate}.
	 *
	 * @param certificate
	 *            the certificate
	 * @return the issued by value of the given {@link X509Certificate}.
	 */
	public static String getIssuedBy(final X509Certificate certificate)
	{
		final X500Principal issuedByPrincipal = certificate.getSubjectX500Principal();
		final String issuedBy = issuedByPrincipal.getName();
		return issuedBy;
	}

	/**
	 * Gets the issued to value of the given {@link X509Certificate}.
	 *
	 * @param certificate
	 *            the certificate
	 * @return the issued to value of the given {@link X509Certificate}.
	 */
	public static String getIssuedTo(final X509Certificate certificate)
	{
		final X500Principal issuedToPrincipal = certificate.getIssuerX500Principal();
		final String issuedTo = issuedToPrincipal.getName();
		return issuedTo;
	}

	/**
	 * Gets the locality value of the given {@link X509Certificate}.
	 *
	 * @param certificate
	 *            the certificate
	 * @return the locality
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static String getLocality(final X509Certificate certificate)
		throws CertificateEncodingException
	{
		return getFirstValueOf(certificate, BCStyle.L);
	}

	/**
	 * Gets the organization value of the given {@link X509Certificate}.
	 *
	 * @param certificate
	 *            the certificate
	 * @return the organization
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static String getOrganization(final X509Certificate certificate)
		throws CertificateEncodingException
	{
		return getFirstValueOf(certificate, BCStyle.O);
	}

	/**
	 * Gets the signature algorithm.
	 *
	 * @param certificate
	 *            the certificate
	 * @return the signature algorithm
	 */
	public static String getSignatureAlgorithm(final X509Certificate certificate)
	{
		return certificate.getSigAlgName();
	}

	/**
	 * Gets the valid from of the given {@link X509Certificate}.
	 *
	 * @param certificate
	 *            the certificate
	 * @return the {@link Date} that represents from when the given {@link X509Certificate} object
	 *         is valid from.
	 */
	public static Date getValidFrom(final X509Certificate certificate)
	{
		return certificate.getNotBefore();
	}

	/**
	 * Gets the valid until of the given {@link X509Certificate}.
	 *
	 * @param certificate
	 *            the certificate
	 * @return the {@link Date} that represents from when the given {@link X509Certificate} object
	 *         is valid until.
	 */
	public static Date getValidUntil(final X509Certificate certificate)
	{
		return certificate.getNotAfter();
	}
}
