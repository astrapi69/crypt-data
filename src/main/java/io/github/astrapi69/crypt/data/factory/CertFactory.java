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
package io.github.astrapi69.crypt.data.factory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import io.github.astrapi69.crypt.api.provider.SecurityProvider;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The factory class {@link CertFactory} holds methods for creating {@link Certificate} objects and
 * subclasses like {@link X509Certificate}. Note: a very good entry point for creating yourself
 * certificate you can follow this <a href=
 * "http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation">link</a>
 */
public final class CertFactory
{

	private CertFactory()
	{
	}

	/**
	 * Factory method for creating a new intermediate {@link X509Certificate} object of version 3 of
	 * X.509 from the given parameters that can be used as an end entity certificate.
	 *
	 * @param keyPair
	 *            the key pair
	 * @param issuer
	 *            X500Name representing the issuer of this certificate.
	 * @param serial
	 *            the serial number for the certificate.
	 * @param notBefore
	 *            date before which the certificate is not valid.
	 * @param notAfter
	 *            date after which the certificate is not valid.
	 * @param subject
	 *            X500Name representing the subject of this certificate.
	 * @param signatureAlgorithm
	 *            the signature algorithm i.e 'SHA1withRSA'
	 * @param caCert
	 *            the ca cert
	 * @return the {@link X509Certificate} object
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider.
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static X509Certificate newEndEntityX509CertificateV3(KeyPair keyPair, X500Name issuer,
		BigInteger serial, Date notBefore, Date notAfter, X500Name subject,
		String signatureAlgorithm, X509Certificate caCert) throws NoSuchAlgorithmException,
		OperatorCreationException, CertificateException, IOException
	{
		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		final Extension authorityKeyIdentifier = new Extension(Extension.authorityKeyIdentifier,
			false,
			extensionUtils.createAuthorityKeyIdentifier(caCert).toASN1Primitive().getEncoded());
		final Extension subjectKeyIdentifier = new Extension(Extension.subjectKeyIdentifier, false,
			extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()).toASN1Primitive()
				.getEncoded());
		final Extension basicConstraints = new Extension(Extension.basicConstraints, false,
			new BasicConstraints(false).toASN1Primitive().getEncoded());
		final Extension keyUsage = new Extension(Extension.keyUsage, false,
			new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).toASN1Primitive()
				.getEncoded());
		return newX509CertificateV3(keyPair, issuer, serial, notBefore, notAfter, subject,
			signatureAlgorithm, authorityKeyIdentifier, subjectKeyIdentifier, basicConstraints,
			keyUsage);
	}

	/**
	 * Factory method for creating a new intermediate {@link X509Certificate} object of version 3 of
	 * X.509 from the given parameters that can be used to sign other certificates.
	 *
	 * @param keyPair
	 *            the key pair
	 * @param issuer
	 *            X500Name representing the issuer of this certificate.
	 * @param serial
	 *            the serial number for the certificate.
	 * @param notBefore
	 *            date before which the certificate is not valid.
	 * @param notAfter
	 *            date after which the certificate is not valid.
	 * @param subject
	 *            X500Name representing the subject of this certificate.
	 * @param signatureAlgorithm
	 *            the signature algorithm i.e 'SHA1withRSA'
	 * @param caCert
	 *            the v1 ca certificate
	 * @return the {@link X509Certificate} object
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static X509Certificate newIntermediateX509CertificateV3(KeyPair keyPair, X500Name issuer,
		BigInteger serial, Date notBefore, Date notAfter, X500Name subject,
		String signatureAlgorithm, X509Certificate caCert) throws NoSuchAlgorithmException,
		OperatorCreationException, CertificateException, IOException
	{
		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		final Extension authorityKeyIdentifier = new Extension(Extension.authorityKeyIdentifier,
			false,
			extensionUtils.createAuthorityKeyIdentifier(caCert).toASN1Primitive().getEncoded());
		final Extension subjectKeyIdentifier = new Extension(Extension.subjectKeyIdentifier, false,
			extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()).toASN1Primitive()
				.getEncoded());
		final Extension basicConstraints = new Extension(Extension.basicConstraints, false,
			new BasicConstraints(0).toASN1Primitive().getEncoded());
		final Extension keyUsage = new Extension(Extension.keyUsage, false,
			new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).toASN1Primitive()
				.getEncoded());
		return newX509CertificateV3(keyPair, issuer, serial, notBefore, notAfter, subject,
			signatureAlgorithm, authorityKeyIdentifier, subjectKeyIdentifier, basicConstraints,
			keyUsage);
	}

	/**
	 * Factory method for creating an initial new {@link X509Certificate} object of version 3 of
	 * type X.509 from the given parameters without an existing certificate.
	 *
	 * @param publicKey
	 *            the public key
	 * @param privateKey
	 *            the private key
	 * @param serialNumber
	 *            the serial number
	 * @param subject
	 *            the subject
	 * @param issuer
	 *            the issuer
	 * @param signatureAlgorithm
	 *            the signature algorithm
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @return the new {@link X509Certificate} object
	 *
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 * @throws IllegalStateException
	 *             is thrown if an illegal state occurs on the generation process
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 */
	public static X509Certificate newX509Certificate(final PublicKey publicKey,
		final PrivateKey privateKey, final BigInteger serialNumber, final String subject,
		final String issuer, final String signatureAlgorithm, final Date start, final Date end)
		throws CertificateException, IllegalStateException, OperatorCreationException
	{
		X509v3CertificateBuilder certBuilder = CertificateBuilderFactory
			.newX509v3CertificateBuilder(new X500Name(issuer), serialNumber, start, end,
				new X500Name(subject), publicKey);
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
			.setProvider(SecurityProvider.BC.name()).build(privateKey);
		return new JcaX509CertificateConverter().setProvider(SecurityProvider.BC.name())
			.getCertificate(certBuilder.build(signer));
	}

	/**
	 * Factory method for creating a new {@link X509Certificate} from the given certificate type and
	 * certificate data as byte array.
	 *
	 * @param type
	 *            the certificate type
	 * @param certificateData
	 *            the certificate data as byte array
	 * @return the new {@link X509Certificate}
	 * @throws CertificateException
	 *             is thrown if no Provider supports a CertificateFactorySpi implementation for the
	 *             given certificate type
	 */
	public static X509Certificate newX509Certificate(final String type,
		final byte[] certificateData) throws CertificateException
	{
		final CertificateFactory cf = CertificateFactory.getInstance(type);
		final InputStream inputStream = new ByteArrayInputStream(certificateData);
		return (X509Certificate)cf.generateCertificate(inputStream);
	}

	/**
	 * Factory method for creating a new {@link X509Certificate} object of the first version of
	 * X.509 from the given parameters. SecurityProvider is Bouncy Castle.
	 *
	 * @param keyPair
	 *            the key pair
	 * @param issuer
	 *            X500Name representing the issuer of this certificate.
	 * @param serial
	 *            the serial number for the certificate.
	 * @param notBefore
	 *            date before which the certificate is not valid.
	 * @param notAfter
	 *            date after which the certificate is not valid.
	 * @param subject
	 *            X500Name representing the subject of this certificate.
	 *
	 * @param signatureAlgorithm
	 *            the signature algorithm i.e 'SHA1withRSA'
	 * @return the new {@link X509Certificate} object
	 *
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 */
	public static X509Certificate newX509CertificateV1(KeyPair keyPair, X500Name issuer,
		BigInteger serial, Date notBefore, Date notAfter, X500Name subject,
		String signatureAlgorithm) throws OperatorCreationException, CertificateException
	{
		X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(issuer, serial,
			notBefore, notAfter, subject, keyPair.getPublic());
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
			.setProvider(SecurityProvider.BC.name()).build(keyPair.getPrivate());
		return new JcaX509CertificateConverter().setProvider(SecurityProvider.BC.name())
			.getCertificate(certBuilder.build(signer));
	}

	/**
	 * Factory method for creating a new intermediate {@link X509Certificate} object of version 3 of
	 * X.509 from the given parameters that can be used as an end entity certificate.
	 *
	 * @param keyPair
	 *            the key pair
	 * @param issuer
	 *            X500Name representing the issuer of this certificate.
	 * @param serial
	 *            the serial number for the certificate.
	 * @param notBefore
	 *            date before which the certificate is not valid.
	 * @param notAfter
	 *            date after which the certificate is not valid.
	 * @param subject
	 *            X500Name representing the subject of this certificate.
	 * @param signatureAlgorithm
	 *            the signature algorithm i.e 'SHA1withRSA'
	 * @param extensions
	 *            the extensions
	 * @return the {@link X509Certificate} object
	 *
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 */
	public static X509Certificate newX509CertificateV3(KeyPair keyPair, X500Name issuer,
		BigInteger serial, Date notBefore, Date notAfter, X500Name subject,
		String signatureAlgorithm, Extension... extensions)
		throws OperatorCreationException, CertificateException
	{
		X509v3CertificateBuilder certBuilder = CertificateBuilderFactory
			.newX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject,
				keyPair.getPublic());
		if (extensions != null && 0 < extensions.length)
		{
			Arrays.stream(extensions)
				.forEach(RuntimeExceptionDecorator.decorate(certBuilder::addExtension));
		}
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
			.setProvider(SecurityProvider.BC.name()).build(keyPair.getPrivate());
		return new JcaX509CertificateConverter().setProvider(SecurityProvider.BC.name())
			.getCertificate(certBuilder.build(signer));
	}

}
