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

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Map;

import io.github.astrapi69.crypt.data.model.Validity;

/**
 * The class {@link CertificateModel} represents a certificate model in a cryptographic system. It
 * contains details about the certificate such as issuer, public key, serial number, signature
 * algorithm, subject, validity period, version, and x509v3 extensions.
 */
public class CertificateModel
{
	/** The issuer of the certificate. */
	private String issuer;

	/** The public key associated with the certificate. */
	private PublicKey publicKey;

	/** The serial number of the certificate. */
	private BigInteger serialNumber;

	/** The signature algorithm used for the certificate. */
	private String signatureAlgorithm;

	/** The subject of the certificate. */
	private String subject;

	/** The validity period of the certificate. */
	private Validity validity;

	/** The version of the certificate. */
	private int version;

	/** The x509v3 extensions of the certificate. */
	private Map<String, String> x509v3Extensions;

	/**
	 * Instantiates a new {@link CertificateModel} with no parameters.
	 */
	public CertificateModel()
	{
	}

	/**
	 * Instantiates a new {@link CertificateModel} from a builder.
	 *
	 * @param b
	 *            the builder used to instantiate the certificate model
	 */
	protected CertificateModel(CertificateInfoBuilder<?, ?> b)
	{
		this.version = b.version;
		this.serialNumber = b.serialNumber;
		this.issuer = b.issuer;
		this.subject = b.subject;
		this.validity = b.validity;
		this.publicKey = b.publicKey;
		this.signatureAlgorithm = b.signatureAlgorithm;
		this.x509v3Extensions = b.x509v3Extensions;
	}

	/**
	 * Instantiates a new {@link CertificateModel} with the specified parameters.
	 *
	 * @param version
	 *            the version of the certificate
	 * @param serialNumber
	 *            the serial number of the certificate
	 * @param issuer
	 *            the issuer of the certificate
	 * @param subject
	 *            the subject of the certificate
	 * @param validity
	 *            the validity period of the certificate
	 * @param publicKey
	 *            the public key associated with the certificate
	 * @param signatureAlgorithm
	 *            the signature algorithm used for the certificate
	 * @param x509v3Extensions
	 *            the x509v3 extensions of the certificate
	 */
	public CertificateModel(int version, BigInteger serialNumber, String issuer, String subject,
		Validity validity, PublicKey publicKey, String signatureAlgorithm,
		Map<String, String> x509v3Extensions)
	{
		this.version = version;
		this.serialNumber = serialNumber;
		this.issuer = issuer;
		this.subject = subject;
		this.validity = validity;
		this.publicKey = publicKey;
		this.signatureAlgorithm = signatureAlgorithm;
		this.x509v3Extensions = x509v3Extensions;
	}

	/**
	 * Creates a new builder for {@link CertificateModel}.
	 *
	 * @return a new builder for {@link CertificateModel}
	 */
	public static CertificateInfoBuilder<?, ?> builder()
	{
		return new CertificateInfoBuilderImpl();
	}

	/**
	 * Checks if the other object is an instance of {@link CertificateModel}.
	 *
	 * @param other
	 *            the other object to check
	 * @return true if the other object is an instance of {@link CertificateModel}, false otherwise
	 */
	protected boolean canEqual(final Object other)
	{
		return other instanceof CertificateModel;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof CertificateModel))
			return false;
		final CertificateModel other = (CertificateModel)o;
		if (!other.canEqual(this))
			return false;
		if (this.getVersion() != other.getVersion())
			return false;
		final Object this$serialNumber = this.getSerialNumber();
		final Object other$serialNumber = other.getSerialNumber();
		if (this$serialNumber == null
			? other$serialNumber != null
			: !this$serialNumber.equals(other$serialNumber))
			return false;
		final Object this$issuer = this.getIssuer();
		final Object other$issuer = other.getIssuer();
		if (this$issuer == null ? other$issuer != null : !this$issuer.equals(other$issuer))
			return false;
		final Object this$subject = this.getSubject();
		final Object other$subject = other.getSubject();
		if (this$subject == null ? other$subject != null : !this$subject.equals(other$subject))
			return false;
		final Object this$validity = this.getValidity();
		final Object other$validity = other.getValidity();
		if (this$validity == null ? other$validity != null : !this$validity.equals(other$validity))
			return false;
		final Object this$publicKey = this.getPublicKey();
		final Object other$publicKey = other.getPublicKey();
		if (this$publicKey == null
			? other$publicKey != null
			: !this$publicKey.equals(other$publicKey))
			return false;
		final Object this$signatureAlgorithm = this.getSignatureAlgorithm();
		final Object other$signatureAlgorithm = other.getSignatureAlgorithm();
		if (this$signatureAlgorithm == null
			? other$signatureAlgorithm != null
			: !this$signatureAlgorithm.equals(other$signatureAlgorithm))
			return false;
		final Object this$x509v3Extensions = this.getX509v3Extensions();
		final Object other$x509v3Extensions = other.getX509v3Extensions();
		return this$x509v3Extensions == null
			? other$x509v3Extensions == null
			: this$x509v3Extensions.equals(other$x509v3Extensions);
	}

	/**
	 * Gets the issuer of the certificate.
	 *
	 * @return the issuer of the certificate
	 */
	public String getIssuer()
	{
		return this.issuer;
	}

	/**
	 * Sets the issuer of the certificate.
	 *
	 * @param issuer
	 *            the new issuer of the certificate
	 */
	public void setIssuer(String issuer)
	{
		this.issuer = issuer;
	}

	/**
	 * Gets the public key associated with the certificate.
	 *
	 * @return the public key associated with the certificate
	 */
	public PublicKey getPublicKey()
	{
		return this.publicKey;
	}

	/**
	 * Sets the public key associated with the certificate.
	 *
	 * @param publicKey
	 *            the new public key associated with the certificate
	 */
	public void setPublicKey(PublicKey publicKey)
	{
		this.publicKey = publicKey;
	}

	/**
	 * Gets the serial number of the certificate.
	 *
	 * @return the serial number of the certificate
	 */
	public BigInteger getSerialNumber()
	{
		return this.serialNumber;
	}

	/**
	 * Sets the serial number of the certificate.
	 *
	 * @param serialNumber
	 *            the new serial number of the certificate
	 */
	public void setSerialNumber(BigInteger serialNumber)
	{
		this.serialNumber = serialNumber;
	}

	/**
	 * Gets the signature algorithm used for the certificate.
	 *
	 * @return the signature algorithm used for the certificate
	 */
	public String getSignatureAlgorithm()
	{
		return this.signatureAlgorithm;
	}

	/**
	 * Sets the signature algorithm used for the certificate.
	 *
	 * @param signatureAlgorithm
	 *            the new signature algorithm used for the certificate
	 */
	public void setSignatureAlgorithm(String signatureAlgorithm)
	{
		this.signatureAlgorithm = signatureAlgorithm;
	}

	/**
	 * Gets the subject of the certificate.
	 *
	 * @return the subject of the certificate
	 */
	public String getSubject()
	{
		return this.subject;
	}

	/**
	 * Sets the subject of the certificate.
	 *
	 * @param subject
	 *            the new subject of the certificate
	 */
	public void setSubject(String subject)
	{
		this.subject = subject;
	}

	/**
	 * Gets the validity period of the certificate.
	 *
	 * @return the validity period of the certificate
	 */
	public Validity getValidity()
	{
		return this.validity;
	}

	/**
	 * Sets the validity period of the certificate.
	 *
	 * @param validity
	 *            the new validity period of the certificate
	 */
	public void setValidity(Validity validity)
	{
		this.validity = validity;
	}

	/**
	 * Gets the version of the certificate.
	 *
	 * @return the version of the certificate
	 */
	public int getVersion()
	{
		return this.version;
	}

	/**
	 * Sets the version of the certificate.
	 *
	 * @param version
	 *            the new version of the certificate
	 */
	public void setVersion(int version)
	{
		this.version = version;
	}

	/**
	 * Gets the x509v3 extensions of the certificate.
	 *
	 * @return the x509v3 extensions of the certificate
	 */
	public Map<String, String> getX509v3Extensions()
	{
		return this.x509v3Extensions;
	}

	/**
	 * Sets the x509v3 extensions of the certificate.
	 *
	 * @param x509v3Extensions
	 *            the new x509v3 extensions of the certificate
	 */
	public void setX509v3Extensions(Map<String, String> x509v3Extensions)
	{
		this.x509v3Extensions = x509v3Extensions;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		result = result * PRIME + this.getVersion();
		final Object $serialNumber = this.getSerialNumber();
		result = result * PRIME + ($serialNumber == null ? 43 : $serialNumber.hashCode());
		final Object $issuer = this.getIssuer();
		result = result * PRIME + ($issuer == null ? 43 : $issuer.hashCode());
		final Object $subject = this.getSubject();
		result = result * PRIME + ($subject == null ? 43 : $subject.hashCode());
		final Object $validity = this.getValidity();
		result = result * PRIME + ($validity == null ? 43 : $validity.hashCode());
		final Object $publicKey = this.getPublicKey();
		result = result * PRIME + ($publicKey == null ? 43 : $publicKey.hashCode());
		final Object $signatureAlgorithm = this.getSignatureAlgorithm();
		result = result * PRIME
			+ ($signatureAlgorithm == null ? 43 : $signatureAlgorithm.hashCode());
		final Object $x509v3Extensions = this.getX509v3Extensions();
		result = result * PRIME + ($x509v3Extensions == null ? 43 : $x509v3Extensions.hashCode());
		return result;
	}

	/**
	 * Creates a builder from the current {@link CertificateModel}.
	 *
	 * @return a builder with the current {@link CertificateModel}'s values
	 */
	public CertificateInfoBuilder<?, ?> toBuilder()
	{
		return new CertificateInfoBuilderImpl().$fillValuesFrom(this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString()
	{
		return "CertificateModel(version=" + this.getVersion() + ", serialNumber="
			+ this.getSerialNumber() + ", issuer=" + this.getIssuer() + ", subject="
			+ this.getSubject() + ", validity=" + this.getValidity() + ", publicKey="
			+ this.getPublicKey() + ", signatureAlgorithm=" + this.getSignatureAlgorithm()
			+ ", x509v3Extensions=" + this.getX509v3Extensions() + ")";
	}

	/**
	 * The builder class for {@link CertificateModel}.
	 *
	 * @param <C>
	 *            the type of the certificate model
	 * @param <B>
	 *            the type of the builder
	 */
	public static abstract class CertificateInfoBuilder<C extends CertificateModel, B extends CertificateInfoBuilder<C, B>>
	{
		private String issuer;
		private PublicKey publicKey;
		private BigInteger serialNumber;
		private String signatureAlgorithm;
		private String subject;
		private Validity validity;
		private int version;
		private Map<String, String> x509v3Extensions;

		/**
		 * Fills the builder with values from the given {@link CertificateModel} instance.
		 *
		 * @param instance
		 *            the instance to copy values from
		 * @param b
		 *            the builder to fill
		 */
		private static void $fillValuesFromInstanceIntoBuilder(CertificateModel instance,
			CertificateInfoBuilder<?, ?> b)
		{
			b.version(instance.version);
			b.serialNumber(instance.serialNumber);
			b.issuer(instance.issuer);
			b.subject(instance.subject);
			b.validity(instance.validity);
			b.publicKey(instance.publicKey);
			b.signatureAlgorithm(instance.signatureAlgorithm);
			b.x509v3Extensions(instance.x509v3Extensions);
		}

		/**
		 * Fills the builder with values from the given {@link CertificateModel} instance.
		 *
		 * @param instance
		 *            the instance to copy values from
		 * @return the builder with copied values
		 */
		protected B $fillValuesFrom(C instance)
		{
			CertificateInfoBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
			return self();
		}

		/**
		 * Builds the {@link CertificateModel}.
		 *
		 * @return the built {@link CertificateModel}
		 */
		public abstract C build();

		/**
		 * Sets the issuer of the certificate.
		 *
		 * @param issuer
		 *            the new issuer
		 * @return the builder instance
		 */
		public B issuer(String issuer)
		{
			this.issuer = issuer;
			return self();
		}

		/**
		 * Sets the public key of the certificate.
		 *
		 * @param publicKey
		 *            the new public key
		 * @return the builder instance
		 */
		public B publicKey(PublicKey publicKey)
		{
			this.publicKey = publicKey;
			return self();
		}

		/**
		 * Returns the builder itself.
		 *
		 * @return the builder instance
		 */
		protected abstract B self();

		/**
		 * Sets the serial number of the certificate.
		 *
		 * @param serialNumber
		 *            the new serial number
		 * @return the builder instance
		 */
		public B serialNumber(BigInteger serialNumber)
		{
			this.serialNumber = serialNumber;
			return self();
		}

		/**
		 * Sets the signature algorithm of the certificate.
		 *
		 * @param signatureAlgorithm
		 *            the new signature algorithm
		 * @return the builder instance
		 */
		public B signatureAlgorithm(String signatureAlgorithm)
		{
			this.signatureAlgorithm = signatureAlgorithm;
			return self();
		}

		/**
		 * Sets the subject of the certificate.
		 *
		 * @param subject
		 *            the new subject
		 * @return the builder instance
		 */
		public B subject(String subject)
		{
			this.subject = subject;
			return self();
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public String toString()
		{
			return "CertificateModel.CertificateInfoBuilder(version=" + this.version
				+ ", serialNumber=" + this.serialNumber + ", issuer=" + this.issuer + ", subject="
				+ this.subject + ", validity=" + this.validity + ", publicKey=" + this.publicKey
				+ ", signatureAlgorithm=" + this.signatureAlgorithm + ", x509v3Extensions="
				+ this.x509v3Extensions + ")";
		}

		/**
		 * Sets the validity period of the certificate.
		 *
		 * @param validity
		 *            the new validity period
		 * @return the builder instance
		 */
		public B validity(Validity validity)
		{
			this.validity = validity;
			return self();
		}

		/**
		 * Sets the version of the certificate.
		 *
		 * @param version
		 *            the new version
		 * @return the builder instance
		 */
		public B version(int version)
		{
			this.version = version;
			return self();
		}

		/**
		 * Sets the x509v3 extensions of the certificate.
		 *
		 * @param x509v3Extensions
		 *            the new x509v3 extensions
		 * @return the builder instance
		 */
		public B x509v3Extensions(Map<String, String> x509v3Extensions)
		{
			this.x509v3Extensions = x509v3Extensions;
			return self();
		}
	}

	/**
	 * Implementation of the builder for {@link CertificateModel}.
	 */
	private static final class CertificateInfoBuilderImpl
		extends
			CertificateInfoBuilder<CertificateModel, CertificateInfoBuilderImpl>
	{
		private CertificateInfoBuilderImpl()
		{
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public CertificateModel build()
		{
			return new CertificateModel(this);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		protected CertificateModel.CertificateInfoBuilderImpl self()
		{
			return this;
		}
	}
}
