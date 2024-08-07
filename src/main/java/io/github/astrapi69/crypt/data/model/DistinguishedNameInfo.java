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
package io.github.astrapi69.crypt.data.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;

import lombok.AccessLevel;
import lombok.Data;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

/**
 * Data class representing the distinguished name information
 */
@Data
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class DistinguishedNameInfo
{

	/**
	 * Shortcut for country code
	 */
	public static final String SHOTCUT_COUNTRY_CODE = "C";

	/**
	 * Shortcut for state
	 */
	public static final String SHORTCUT_STATE = "ST";

	/**
	 * Shortcut for location
	 */
	public static final String SHORTCUT_LOCATION = "L";

	/**
	 * Shortcut for organisation
	 */
	public static final String SHORTCUT_ORGANISATION = "O";

	/**
	 * Shortcut for organisation unit
	 */
	public static final String SHORTCUT_ORGANISATION_UNIT = "OU";

	/**
	 * Shortcut for common name
	 */
	public static final String SHORTCUT_COMMON_NAME = "CN";

	/**
	 * The common name
	 */
	private String commonName;

	/**
	 * The country code
	 */
	private String countryCode;

	/**
	 * The location
	 */
	private String location;

	/**
	 * The organisation name
	 */
	private String organisation;

	/**
	 * The organisation unit
	 */
	private String organisationUnit;

	/**
	 * The state
	 */
	private String state;

	/**
	 * Converts a representable string to a {@link DistinguishedNameInfo} object
	 *
	 * @param representableString
	 *            the string to convert
	 * @return the corresponding {@link DistinguishedNameInfo} object
	 */
	public static DistinguishedNameInfo toDistinguishedNameInfo(String representableString)
	{
		Map<String, String> map = new HashMap<>();
		String[] parts = representableString.split(",");
		for (String part : parts)
		{
			String[] keyValue = part.trim().split("=");
			if (keyValue.length == 2)
			{
				map.put(keyValue[0].trim(), keyValue[1].trim());
			}
		}
		DistinguishedNameInfo distinguishedNameInfo = DistinguishedNameInfo.builder()
			.countryCode(map.get(SHOTCUT_COUNTRY_CODE)).state(map.get(SHORTCUT_STATE))
			.location(map.get(SHORTCUT_LOCATION)).organisation(map.get(SHORTCUT_ORGANISATION))
			.organisationUnit(map.get(SHORTCUT_ORGANISATION_UNIT))
			.commonName(map.get(SHORTCUT_COMMON_NAME)).build();

		return distinguishedNameInfo;
	}

	/**
	 * Converts this {@link DistinguishedNameInfo} object to a representable string
	 *
	 * @return the corresponding string representation of this {@link DistinguishedNameInfo} object
	 */
	public String toRepresentableString()
	{
		return DistinguishedNameInfo.toRepresentableString(this);
	}

	/**
	 * Converts this {@link DistinguishedNameInfo} object to a {@link X500Name} object
	 *
	 * @return the corresponding {@link X500Name} object of this {@link DistinguishedNameInfo}
	 *         object
	 */
	public X500Name toX500Name()
	{
		return new X500Name(toRepresentableString());
	}

	/**
	 * Converts the {@link DistinguishedNameInfo} object to a {@link X500Name} object
	 *
	 * @param distinguishedNameInfo
	 *            the {@link DistinguishedNameInfo} object to convert
	 * @return the corresponding {@link X500Name} object
	 */
	public static X500Name toX500Name(@NonNull DistinguishedNameInfo distinguishedNameInfo)
	{
		return distinguishedNameInfo.toX500Name();
	}

	/**
	 * Converts the {@link DistinguishedNameInfo} object to a representable string
	 *
	 * @param distinguishedNameInfo
	 *            the {@link DistinguishedNameInfo} object to convert
	 * @return the corresponding string representation
	 */
	public static String toRepresentableString(DistinguishedNameInfo distinguishedNameInfo)
	{
		List<String> parts = new ArrayList<>();
		addCertificateValue(parts, SHORTCUT_COMMON_NAME, distinguishedNameInfo.commonName);
		addCertificateValue(parts, SHORTCUT_ORGANISATION_UNIT,
			distinguishedNameInfo.organisationUnit);
		addCertificateValue(parts, SHORTCUT_ORGANISATION, distinguishedNameInfo.organisation);
		addCertificateValue(parts, SHORTCUT_LOCATION, distinguishedNameInfo.location);
		addCertificateValue(parts, SHORTCUT_STATE, distinguishedNameInfo.state);
		addCertificateValue(parts, SHOTCUT_COUNTRY_CODE, distinguishedNameInfo.countryCode);
		return String.join(",", parts);
	}

	/**
	 * Adds the certificate value to the list if it is not null or empty
	 *
	 * @param parts
	 *            the list to add the value to
	 * @param key
	 *            the key representing the certificate field
	 * @param certificateValue
	 *            the value of the certificate field
	 */
	private static void addCertificateValue(List<String> parts, String key, String certificateValue)
	{
		if (certificateValue != null && !certificateValue.isEmpty())
		{
			parts.add(key + "=" + certificateValue);
		}
	}
}
