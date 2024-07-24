package io.github.astrapi69.crypt.data.model;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;

import lombok.AccessLevel;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

/**
 * Data class representing extension information
 */
@Data
@RequiredArgsConstructor
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ExtensionInfo
{
	/**
	 * The identifier of the extension.
	 */
	String extensionId;

	/**
	 * Indicates whether the extension is critical.
	 */
	boolean critical;

	/**
	 * The value of the extension.
	 */
	String value;

	/**
	 * Converts an {@link ExtensionInfo} object to a {@link Extension} object.
	 *
	 * @param extensionInfo
	 *            the {@link ExtensionInfo} object to convert.
	 * @return the corresponding {@link Extension} object.
	 */
	public static Extension toExtension(final ExtensionInfo extensionInfo)
	{
		ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(extensionInfo.getExtensionId());
		byte[] extensionValue = extensionInfo.getValue().getBytes();
		ASN1OctetString value = new DEROctetString(extensionValue);
		return new Extension(oid, extensionInfo.isCritical(), value);
	}

	/**
	 * Factory method to create an {@link ExtensionInfo} object from a {@link Extension} object.
	 *
	 * @param extension
	 *            the {@link Extension} object to convert.
	 * @return the corresponding {@link ExtensionInfo} object.
	 */
	public static ExtensionInfo fromExtension(final Extension extension)
	{
		String extensionId = extension.getExtnId().getId();
		boolean critical = extension.isCritical();
		String value = new String(extension.getExtnValue().getOctets());

		return ExtensionInfo.builder().extensionId(extensionId).critical(critical).value(value)
			.build();
	}

	/**
	 * Extracts extension-infos from an {@link X509Certificate} and returns them as a list of
	 * {@link ExtensionInfo} objects
	 *
	 * @param certificate
	 *            the {@link X509Certificate} to extract extensions from.
	 * @return a list of {@link ExtensionInfo} objects.
	 */
	public static List<ExtensionInfo> extractExtensionInfos(X509Certificate certificate)
	{
		List<ExtensionInfo> extensions = new ArrayList<>();

		Set<String> criticalOIDs = certificate.getCriticalExtensionOIDs();
		if (criticalOIDs != null)
		{
			for (String oid : criticalOIDs)
			{
				byte[] extensionValue = certificate.getExtensionValue(oid);
				Extension extension = new Extension(new ASN1ObjectIdentifier(oid), true,
					new DEROctetString(extensionValue));
				extensions.add(ExtensionInfo.fromExtension(extension));
			}
		}

		Set<String> nonCriticalOIDs = certificate.getNonCriticalExtensionOIDs();
		if (nonCriticalOIDs != null)
		{
			for (String oid : nonCriticalOIDs)
			{
				byte[] extensionValue = certificate.getExtensionValue(oid);
				Extension extension = new Extension(new ASN1ObjectIdentifier(oid), false,
					new DEROctetString(extensionValue));
				extensions.add(ExtensionInfo.fromExtension(extension));
			}
		}

		return extensions;
	}

	/**
	 * Extracts extension-infos from an {@link X509Certificate} and returns them as an array of
	 * {@link ExtensionInfo} objects.
	 *
	 * @param certificate
	 *            the {@link X509Certificate} to extract extensions from.
	 * @return an array of {@link ExtensionInfo} objects.
	 */
	public static ExtensionInfo[] extractToExtensionInfoArray(X509Certificate certificate)
	{
		return extractExtensionInfos(certificate).toArray(new ExtensionInfo[0]);
	}
}
