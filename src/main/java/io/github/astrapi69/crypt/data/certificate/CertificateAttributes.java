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
package io.github.astrapi69.crypt.data.certificate;

/**
 * The type Certificate attributes.
 *
 * @deprecated use instead the class
 *             {@link io.github.astrapi69.crypt.data.model.DistinguishedNameInfo}. Note will be
 *             removed in next minor version
 */
@Deprecated
public class CertificateAttributes
{
	private String commonName;
	private String countryCode;
	private String location;
	private String organisation;
	private String organisationUnit;
	private String state;

	/**
	 * Instantiates a new Certificate attributes.
	 */
	public CertificateAttributes()
	{
	}

	/**
	 * Instantiates a new Certificate attributes.
	 *
	 * @param b
	 *            the b
	 */
	protected CertificateAttributes(CertificateAttributesBuilder<?, ?> b)
	{
		this.commonName = b.commonName;
		this.organisation = b.organisation;
		this.organisationUnit = b.organisationUnit;
		this.countryCode = b.countryCode;
		this.state = b.state;
		this.location = b.location;
	}

	/**
	 * Instantiates a new Certificate attributes.
	 *
	 * @param commonName
	 *            the common name
	 * @param organisation
	 *            the organisation
	 * @param organisationUnit
	 *            the organisation unit
	 * @param countryCode
	 *            the country code
	 * @param state
	 *            the state
	 * @param location
	 *            the location
	 */
	public CertificateAttributes(String commonName, String organisation, String organisationUnit,
		String countryCode, String state, String location)
	{
		this.commonName = commonName;
		this.organisation = organisation;
		this.organisationUnit = organisationUnit;
		this.countryCode = countryCode;
		this.state = state;
		this.location = location;
	}

	/**
	 * Builder certificate attributes builder.
	 *
	 * @return the certificate attributes builder
	 */
	public static CertificateAttributesBuilder<?, ?> builder()
	{
		return new CertificateAttributesBuilderImpl();
	}

	/**
	 * Can equal boolean.
	 *
	 * @param other
	 *            the other
	 * @return the boolean
	 */
	protected boolean canEqual(final Object other)
	{
		return other instanceof CertificateAttributes;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof CertificateAttributes))
			return false;
		final CertificateAttributes other = (CertificateAttributes)o;
		if (!other.canEqual(this))
			return false;
		final Object this$commonName = this.getCommonName();
		final Object other$commonName = other.getCommonName();
		if (this$commonName == null
			? other$commonName != null
			: !this$commonName.equals(other$commonName))
			return false;
		final Object this$organisation = this.getOrganisation();
		final Object other$organisation = other.getOrganisation();
		if (this$organisation == null
			? other$organisation != null
			: !this$organisation.equals(other$organisation))
			return false;
		final Object this$organisationUnit = this.getOrganisationUnit();
		final Object other$organisationUnit = other.getOrganisationUnit();
		if (this$organisationUnit == null
			? other$organisationUnit != null
			: !this$organisationUnit.equals(other$organisationUnit))
			return false;
		final Object this$countryCode = this.getCountryCode();
		final Object other$countryCode = other.getCountryCode();
		if (this$countryCode == null
			? other$countryCode != null
			: !this$countryCode.equals(other$countryCode))
			return false;
		final Object this$state = this.getState();
		final Object other$state = other.getState();
		if (this$state == null ? other$state != null : !this$state.equals(other$state))
			return false;
		final Object this$location = this.getLocation();
		final Object other$location = other.getLocation();
		return this$location == null
			? other$location == null
			: this$location.equals(other$location);
	}

	/**
	 * Gets common name.
	 *
	 * @return the common name
	 */
	public String getCommonName()
	{
		return this.commonName;
	}

	/**
	 * Sets common name.
	 *
	 * @param commonName
	 *            the common name
	 */
	public void setCommonName(String commonName)
	{
		this.commonName = commonName;
	}

	/**
	 * Gets country code.
	 *
	 * @return the country code
	 */
	public String getCountryCode()
	{
		return this.countryCode;
	}

	/**
	 * Sets country code.
	 *
	 * @param countryCode
	 *            the country code
	 */
	public void setCountryCode(String countryCode)
	{
		this.countryCode = countryCode;
	}

	/**
	 * Gets location.
	 *
	 * @return the location
	 */
	public String getLocation()
	{
		return this.location;
	}

	/**
	 * Sets location.
	 *
	 * @param location
	 *            the location
	 */
	public void setLocation(String location)
	{
		this.location = location;
	}

	/**
	 * Gets organisation.
	 *
	 * @return the organisation
	 */
	public String getOrganisation()
	{
		return this.organisation;
	}

	/**
	 * Sets organisation.
	 *
	 * @param organisation
	 *            the organisation
	 */
	public void setOrganisation(String organisation)
	{
		this.organisation = organisation;
	}

	/**
	 * Gets organisation unit.
	 *
	 * @return the organisation unit
	 */
	public String getOrganisationUnit()
	{
		return this.organisationUnit;
	}

	/**
	 * Sets organisation unit.
	 *
	 * @param organisationUnit
	 *            the organisation unit
	 */
	public void setOrganisationUnit(String organisationUnit)
	{
		this.organisationUnit = organisationUnit;
	}

	/**
	 * Gets state.
	 *
	 * @return the state
	 */
	public String getState()
	{
		return this.state;
	}

	/**
	 * Sets state.
	 *
	 * @param state
	 *            the state
	 */
	public void setState(String state)
	{
		this.state = state;
	}

	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $commonName = this.getCommonName();
		result = result * PRIME + ($commonName == null ? 43 : $commonName.hashCode());
		final Object $organisation = this.getOrganisation();
		result = result * PRIME + ($organisation == null ? 43 : $organisation.hashCode());
		final Object $organisationUnit = this.getOrganisationUnit();
		result = result * PRIME + ($organisationUnit == null ? 43 : $organisationUnit.hashCode());
		final Object $countryCode = this.getCountryCode();
		result = result * PRIME + ($countryCode == null ? 43 : $countryCode.hashCode());
		final Object $state = this.getState();
		result = result * PRIME + ($state == null ? 43 : $state.hashCode());
		final Object $location = this.getLocation();
		result = result * PRIME + ($location == null ? 43 : $location.hashCode());
		return result;
	}

	private boolean setCertificateValue(StringBuilder stringBuilder, String key,
		String certificateValue)
	{
		if (certificateValue != null && !certificateValue.isEmpty())
		{
			stringBuilder.append(key).append("=").append(certificateValue);
			return true;
		}
		return false;
	}

	/**
	 * To builder certificate attributes builder.
	 *
	 * @return the certificate attributes builder
	 */
	public CertificateAttributesBuilder<?, ?> toBuilder()
	{
		return new CertificateAttributesBuilderImpl().$fillValuesFrom(this);
	}

	/**
	 * To representable string string.
	 *
	 * @return the string
	 */
	public String toRepresentableString()
	{
		StringBuilder stringBuilder = new StringBuilder();
		if (setCertificateValue(stringBuilder, "C", countryCode))
		{
			stringBuilder.append(", ");
		}
		if (setCertificateValue(stringBuilder, "ST", state))
		{
			stringBuilder.append(", ");
		}
		if (setCertificateValue(stringBuilder, "L", location))
		{
			stringBuilder.append(", ");
		}
		if (setCertificateValue(stringBuilder, "O", organisation))
		{
			stringBuilder.append(", ");
		}
		if (setCertificateValue(stringBuilder, "OU", organisationUnit))
		{
			stringBuilder.append(", ");
		}
		if (setCertificateValue(stringBuilder, "CN", commonName))
		{
			stringBuilder.append(", ");
		}
		String result = stringBuilder.toString();
		if (result.endsWith(", "))
		{
			result = result.substring(0, result.lastIndexOf(", "));
		}
		return result;
	}

	@Override
	public String toString()
	{
		return "CertificateAttributes(commonName=" + this.getCommonName() + ", organisation="
			+ this.getOrganisation() + ", organisationUnit=" + this.getOrganisationUnit()
			+ ", countryCode=" + this.getCountryCode() + ", state=" + this.getState()
			+ ", location=" + this.getLocation() + ")";
	}

	/**
	 * The type Certificate attributes builder.
	 *
	 * @param <C>
	 *            the type parameter
	 * @param <B>
	 *            the type parameter
	 */
	public static abstract class CertificateAttributesBuilder<C extends CertificateAttributes, B extends CertificateAttributes.CertificateAttributesBuilder<C, B>>
	{
		private String commonName;
		private String countryCode;
		private String location;
		private String organisation;
		private String organisationUnit;
		private String state;

		private static void $fillValuesFromInstanceIntoBuilder(CertificateAttributes instance,
			CertificateAttributes.CertificateAttributesBuilder<?, ?> b)
		{
			b.commonName(instance.commonName);
			b.organisation(instance.organisation);
			b.organisationUnit(instance.organisationUnit);
			b.countryCode(instance.countryCode);
			b.state(instance.state);
			b.location(instance.location);
		}

		/**
		 * Fill values from b.
		 *
		 * @param instance
		 *            the instance
		 * @return the b
		 */
		protected B $fillValuesFrom(C instance)
		{
			CertificateAttributesBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
			return self();
		}

		/**
		 * Build c.
		 *
		 * @return the c
		 */
		public abstract C build();

		/**
		 * Common name b.
		 *
		 * @param commonName
		 *            the common name
		 * @return the b
		 */
		public B commonName(String commonName)
		{
			this.commonName = commonName;
			return self();
		}

		/**
		 * Country code b.
		 *
		 * @param countryCode
		 *            the country code
		 * @return the b
		 */
		public B countryCode(String countryCode)
		{
			this.countryCode = countryCode;
			return self();
		}

		/**
		 * Location b.
		 *
		 * @param location
		 *            the location
		 * @return the b
		 */
		public B location(String location)
		{
			this.location = location;
			return self();
		}

		/**
		 * Organisation b.
		 *
		 * @param organisation
		 *            the organisation
		 * @return the b
		 */
		public B organisation(String organisation)
		{
			this.organisation = organisation;
			return self();
		}

		/**
		 * Organisation unit b.
		 *
		 * @param organisationUnit
		 *            the organisation unit
		 * @return the b
		 */
		public B organisationUnit(String organisationUnit)
		{
			this.organisationUnit = organisationUnit;
			return self();
		}

		/**
		 * Self b.
		 *
		 * @return the b
		 */
		protected abstract B self();

		/**
		 * State b.
		 *
		 * @param state
		 *            the state
		 * @return the b
		 */
		public B state(String state)
		{
			this.state = state;
			return self();
		}

		@Override
		public String toString()
		{
			return "CertificateAttributes.CertificateAttributesBuilder(commonName="
				+ this.commonName + ", organisation=" + this.organisation + ", organisationUnit="
				+ this.organisationUnit + ", countryCode=" + this.countryCode + ", state="
				+ this.state + ", location=" + this.location + ")";
		}
	}

	private static final class CertificateAttributesBuilderImpl
		extends
			CertificateAttributesBuilder<CertificateAttributes, CertificateAttributesBuilderImpl>
	{
		private CertificateAttributesBuilderImpl()
		{
		}

		@Override
		public CertificateAttributes build()
		{
			return new CertificateAttributes(this);
		}

		@Override
		protected CertificateAttributes.CertificateAttributesBuilderImpl self()
		{
			return this;
		}
	}
}
