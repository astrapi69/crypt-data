package io.github.astrapi69.crypt.data.processor.certificate;

import static io.github.astrapi69.crypt.data.factory.CertFactory.newX509Certificate;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;
import io.github.astrapi69.crypt.data.factory.CertificateTestDataFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.key.KeySizeExtensions;
import io.github.astrapi69.crypt.data.key.KeySizeInitializer;
import io.github.astrapi69.crypt.data.model.CertificateInfo;
import lombok.extern.java.Log;

/**
 * Utility class for verifying supported signature algorithms based on key pair algorithms and their
 * key sizes The class provides methods to test and verify if a given combination of key pair and
 * signature algorithms can successfully generate an X.509 certificate
 */
@Log
public class CertificateVerifier
{

	/**
	 * Retrieves a map of supported signature algorithms for a specified cryptographic service The
	 * method generates key pairs for each algorithm and key size within the provided range, and
	 * tests whether they can successfully create an X.509 certificate using various signature
	 * algorithms
	 *
	 * @param <T>
	 *            the type of the generator class used to determine key sizes
	 * @param serviceName
	 *            the name of the cryptographic service (e.g., "KeyPairGenerator")
	 * @param generatorClass
	 *            the class of the generator used to produce cryptographic keys
	 * @param initializer
	 *            a functional interface or lambda expression that initializes the generator class
	 *            with a specific key size
	 * @param minSize
	 *            the minimum key size to consider in the analysis
	 * @param maxSize
	 *            the maximum key size to consider in the analysis
	 * @param increment
	 *            the step size for iterating through key sizes between minSize and maxSize
	 * @return a {@code Map<String, Set<String>>} where each key is the name of a key pair
	 *         algorithm, and each value is a set of valid signature algorithms for that algorithm
	 * @throws InvocationTargetException
	 *             if an error occurs while invoking the initializer or generator methods
	 * @throws NoSuchMethodException
	 *             if a necessary method to initialize the generator class cannot be found
	 * @throws IllegalAccessException
	 *             if the initializer or generator method is not accessible
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm cannot be found
	 * @throws NoSuchProviderException
	 *             if the specified provider cannot be found
	 */
	public static <T> Map<String, Set<String>> getSupportedSignatureAlgorithms(String serviceName,
		Class<T> generatorClass, KeySizeInitializer<T> initializer, int minSize, int maxSize,
		int increment) throws InvocationTargetException, NoSuchMethodException,
		IllegalAccessException, NoSuchAlgorithmException, NoSuchProviderException
	{

		Map<String, Set<String>> supportedSignatureAlgorithmsMap = new TreeMap<>();
		Set<String> keyPairAlgorithms = AlgorithmExtensions.getAlgorithms(serviceName);
		Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");

		// Iterate over each key pair algorithm
		for (String keyPairAlgorithm : keyPairAlgorithms)
		{
			// Get supported key sizes for the algorithm
			Set<Integer> supportedKeySizes = KeySizeExtensions.getSupportedKeySizes(
				keyPairAlgorithm, generatorClass, initializer, minSize, maxSize, increment);

			if (!supportedKeySizes.isEmpty())
			{
				List<Integer> keySizesCopy = new ArrayList<>(supportedKeySizes);
				Integer keySize = keySizesCopy.get(0);
				KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairAlgorithm, keySize);
				PrivateKey privateKey = keyPair.getPrivate();
				PublicKey publicKey = keyPair.getPublic();

				// Test each signature algorithm with the key pair
				for (String signatureAlgorithm : signatureAlgorithms)
				{
					CertificateAlgorithmEntry certificateAlgorithmEntry = CertificateAlgorithmEntry
						.builder().keyPairAlgorithm(keyPairAlgorithm)
						.signatureAlgorithm(signatureAlgorithm).build();

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
						if (isAlgorithmValidForCertificate(certificateInfo))
						{
							// Add to the map
							supportedSignatureAlgorithmsMap
								.computeIfAbsent(keyPairAlgorithm, k -> new TreeSet<>())
								.add(signatureAlgorithm);
						}
					}
					catch (Exception e)
					{
						// Handle specific cases where the signature type is unknown
						log.log(Level.WARNING,
							"Unknown signature type: " + certificateInfo.getSignatureAlgorithm(),
							e);
					}
				}
			}
		}

		return supportedSignatureAlgorithmsMap;
	}

	/**
	 * Tests whether a given signature algorithm can be used to successfully create an
	 * {@link X509Certificate}
	 *
	 * @param certificateInfo
	 *            the certificate information containing details like issuer, subject, etc
	 * @return true if the algorithm is valid and can be used to create the certificate, false
	 *         otherwise
	 */
	public static boolean isAlgorithmValidForCertificate(CertificateInfo certificateInfo)
	{
		try
		{
			// Attempt to create the certificate using the given signature algorithm
			X509Certificate certificate = newX509Certificate(certificateInfo);

			// If certificate creation is successful and no exception was thrown, the algorithm is
			// valid
			return certificate != null;
		}
		catch (IllegalArgumentException e)
		{
			// Handle specific cases where the signature type is unknown
			log.log(Level.WARNING,
				"Unknown signature type: " + certificateInfo.getSignatureAlgorithm(), e);
			return false;
		}
		catch (OperatorCreationException | CertificateException | CertIOException e)
		{
			log.log(Level.WARNING, "Certificate creation failed for algorithm: "
				+ certificateInfo.getSignatureAlgorithm(), e);
			return false;
		}
	}

}
