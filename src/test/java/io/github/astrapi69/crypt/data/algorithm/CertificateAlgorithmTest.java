package io.github.astrapi69.crypt.data.algorithm;

import static io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions.getAlgorithmsFromServiceName;
import static io.github.astrapi69.crypt.data.factory.CertFactory.newX509Certificate;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.factory.CertificateTestDataFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.model.CertificateInfo;
import lombok.NonNull;
import lombok.extern.java.Log;

/**
 * Utility class to resolve and test appropriate signature algorithms for X.509 certificate
 * creation.
 */
@Log
public class CertificateAlgorithmTest
{

	/**
	 * Tests and retrieves a list of valid signature algorithms that can be used to create an
	 * {@link X509Certificate} using the given certificate information.
	 *
	 * @param certificateInfo
	 *            the certificate information containing details like issuer, subject, etc.
	 * @param serviceName
	 *            the name of the service, typically "Signature"
	 * @return a list of valid signature algorithms that do not throw exceptions during certificate
	 *         creation
	 */
	public static List<String> getValidSignatureAlgorithms(final CertificateInfo certificateInfo,
		final @NonNull String serviceName)
	{
		Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms(serviceName);

		// Filter and test each algorithm, returning only those that are valid
		return signatureAlgorithms.stream()
			.filter(signatureAlgorithm -> isAlgorithmValidForCertificate(certificateInfo,
				signatureAlgorithm))
			.collect(Collectors.toList());
	}

	/**
	 * Tests whether a given signature algorithm can be used to successfully create an
	 * {@link X509Certificate}.
	 *
	 * @param certificateInfo
	 *            the certificate information containing details like issuer, subject, etc.
	 * @param signatureAlgorithm
	 *            the signature algorithm to test
	 * @return true if the algorithm is valid and can be used to create the certificate, false
	 *         otherwise
	 */
	private static boolean isAlgorithmValidForCertificate(CertificateInfo certificateInfo,
		String signatureAlgorithm)
	{
		try
		{
			// Update the certificate info with the current algorithm to test
			certificateInfo.setSignatureAlgorithm(signatureAlgorithm);

			// Attempt to create the certificate using the given signature algorithm
			X509Certificate certificate = newX509Certificate(certificateInfo);

			// If certificate creation is successful and no exception was thrown, the algorithm is
			// valid
			return certificate != null;
		}
		catch (OperatorCreationException | CertificateException | CertIOException e)
		{
			// If any exception occurs, the algorithm is not valid
			return false;
		}
	}


	@Test
	// @Disabled
	public void testAllKeyPairGeneratorAlgorithmsWithSignature()
		throws IOException, InvocationTargetException, NoSuchMethodException, IllegalAccessException
	{

		Set<String> keyPairGeneratorAlgorithms = AlgorithmExtensions
			.getAlgorithms("KeyPairGenerator");
		assertNotNull(keyPairGeneratorAlgorithms);

		Map<String, Set<Integer>> supportedKeySizesForKeyPairGenerator = AlgorithmExtensions
			.getSupportedAlgorithmsAndKeySizes("KeyPairGenerator", KeyPairGenerator.class,
				KeyPairGenerator::initialize, 1, 32768, 1);
		assertEquals(keyPairGeneratorAlgorithms.size(),
			supportedKeySizesForKeyPairGenerator.size());

		supportedKeySizesForKeyPairGenerator.forEach((algorithm, keySizes) -> {

			Runnable task = () -> {
				try
				{
					List<Integer> list = keySizes.stream().toList();
					KeyPair keyPair = KeyPairFactory.newKeyPair(algorithm, list.get(0));
					PrivateKey privateKey = keyPair.getPrivate();
					PublicKey publicKey = keyPair.getPublic();

					List<String> algorithmsFromServiceName = getAlgorithmsFromServiceName(
						"Signature", algorithm);

					algorithmsFromServiceName.forEach(signatureAlgorithm -> {

						CertificateInfo certificateInfo = CertificateInfo.builder()
							.privateKeyInfo(KeyInfoExtensions.toKeyInfo(privateKey))
							.publicKeyInfo(KeyInfoExtensions.toKeyInfo(publicKey))
							.issuer(CertificateTestDataFactory.newIssuerDistinguishedNameInfo())
							.subject(CertificateTestDataFactory.newSubjectDistinguishedNameInfo())
							.serial(CertificateTestDataFactory.newSerialNumber())
							.validity(CertificateTestDataFactory.newValidity())
							.signatureAlgorithm(signatureAlgorithm).version(3)
							.extensions(CertificateTestDataFactory.newExtensionInfos()).build();

						try
						{
							X509Certificate x509Certificate = newX509Certificate(certificateInfo);
						}
						catch (OperatorCreationException e)
						{
							throw new RuntimeException(e);
						}
						catch (CertificateException e)
						{
							throw new RuntimeException(e);
						}
						catch (CertIOException e)
						{
							throw new RuntimeException(e);
						}
					});


				}
				catch (NoSuchAlgorithmException | NoSuchProviderException e)
				{

				}
			};

		});

	}

}
