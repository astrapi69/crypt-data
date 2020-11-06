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
package de.alpharogroup.crypto.certificate;


import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Map;

public class CertificateInfo
{
	public static abstract class CertificateInfoBuilder<C extends CertificateInfo, B extends CertificateInfo.CertificateInfoBuilder<C, B>>
	{
		private static void $fillValuesFromInstanceIntoBuilder(CertificateInfo instance,
			CertificateInfo.CertificateInfoBuilder<?, ?> b)
		{
			b.version(instance.version);
			b.serialNumber(instance.serialNumber);
			b.issuer(instance.issuer);
			b.subject(instance.subject);
			b.valitidy(instance.valitidy);
			b.publicKey(instance.publicKey);
			b.signatureAlgorithm(instance.signatureAlgorithm);
			b.x509v3Extensions(instance.x509v3Extensions);
		}
		private String issuer;
		private PublicKey publicKey;
		private BigInteger serialNumber;
		private String signatureAlgorithm;
		private String subject;
		private Valitidy valitidy;
		private int version;

		private Map<String, String> x509v3Extensions;

		protected B $fillValuesFrom(C instance)
		{
			CertificateInfoBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
			return self();
		}

		public abstract C build();

		public B issuer(String issuer)
		{
			this.issuer = issuer;
			return self();
		}

		public B publicKey(PublicKey publicKey)
		{
			this.publicKey = publicKey;
			return self();
		}

		protected abstract B self();

		public B serialNumber(BigInteger serialNumber)
		{
			this.serialNumber = serialNumber;
			return self();
		}

		public B signatureAlgorithm(String signatureAlgorithm)
		{
			this.signatureAlgorithm = signatureAlgorithm;
			return self();
		}

		public B subject(String subject)
		{
			this.subject = subject;
			return self();
		}

		public String toString()
		{
			return "CertificateInfo.CertificateInfoBuilder(version=" + this.version
				+ ", serialNumber=" + this.serialNumber + ", issuer=" + this.issuer + ", subject="
				+ this.subject + ", valitidy=" + this.valitidy + ", publicKey=" + this.publicKey
				+ ", signatureAlgorithm=" + this.signatureAlgorithm + ", x509v3Extensions="
				+ this.x509v3Extensions + ")";
		}

		public B valitidy(Valitidy valitidy)
		{
			this.valitidy = valitidy;
			return self();
		}

		public B version(int version)
		{
			this.version = version;
			return self();
		}

		public B x509v3Extensions(Map<String, String> x509v3Extensions)
		{
			this.x509v3Extensions = x509v3Extensions;
			return self();
		}
	}
	private static final class CertificateInfoBuilderImpl
		extends
			CertificateInfoBuilder<CertificateInfo, CertificateInfoBuilderImpl>
	{
		private CertificateInfoBuilderImpl()
		{
		}

		public CertificateInfo build()
		{
			return new CertificateInfo(this);
		}

		protected CertificateInfo.CertificateInfoBuilderImpl self()
		{
			return this;
		}
	}
	public static CertificateInfoBuilder<?, ?> builder()
	{
		return new CertificateInfoBuilderImpl();
	}
	private String issuer;
	private PublicKey publicKey;
	private BigInteger serialNumber;
	private String signatureAlgorithm;
	private String subject;

	private Valitidy valitidy;

	private int version;

	private Map<String, String> x509v3Extensions;

	public CertificateInfo()
	{
	}

	protected CertificateInfo(CertificateInfoBuilder<?, ?> b)
	{
		this.version = b.version;
		this.serialNumber = b.serialNumber;
		this.issuer = b.issuer;
		this.subject = b.subject;
		this.valitidy = b.valitidy;
		this.publicKey = b.publicKey;
		this.signatureAlgorithm = b.signatureAlgorithm;
		this.x509v3Extensions = b.x509v3Extensions;
	}

	public CertificateInfo(int version, BigInteger serialNumber, String issuer, String subject,
		Valitidy valitidy, PublicKey publicKey, String signatureAlgorithm,
		Map<String, String> x509v3Extensions)
	{
		this.version = version;
		this.serialNumber = serialNumber;
		this.issuer = issuer;
		this.subject = subject;
		this.valitidy = valitidy;
		this.publicKey = publicKey;
		this.signatureAlgorithm = signatureAlgorithm;
		this.x509v3Extensions = x509v3Extensions;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof CertificateInfo;
	}

	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof CertificateInfo))
			return false;
		final CertificateInfo other = (CertificateInfo)o;
		if (!other.canEqual((Object)this))
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
		final Object this$valitidy = this.getValitidy();
		final Object other$valitidy = other.getValitidy();
		if (this$valitidy == null ? other$valitidy != null : !this$valitidy.equals(other$valitidy))
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
		if (this$x509v3Extensions == null
			? other$x509v3Extensions != null
			: !this$x509v3Extensions.equals(other$x509v3Extensions))
			return false;
		return true;
	}

	public String getIssuer()
	{
		return this.issuer;
	}

	public PublicKey getPublicKey()
	{
		return this.publicKey;
	}

	public BigInteger getSerialNumber()
	{
		return this.serialNumber;
	}

	public String getSignatureAlgorithm()
	{
		return this.signatureAlgorithm;
	}

	public String getSubject()
	{
		return this.subject;
	}

	public Valitidy getValitidy()
	{
		return this.valitidy;
	}

	public int getVersion()
	{
		return this.version;
	}

	public Map<String, String> getX509v3Extensions()
	{
		return this.x509v3Extensions;
	}

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
		final Object $valitidy = this.getValitidy();
		result = result * PRIME + ($valitidy == null ? 43 : $valitidy.hashCode());
		final Object $publicKey = this.getPublicKey();
		result = result * PRIME + ($publicKey == null ? 43 : $publicKey.hashCode());
		final Object $signatureAlgorithm = this.getSignatureAlgorithm();
		result = result * PRIME
			+ ($signatureAlgorithm == null ? 43 : $signatureAlgorithm.hashCode());
		final Object $x509v3Extensions = this.getX509v3Extensions();
		result = result * PRIME + ($x509v3Extensions == null ? 43 : $x509v3Extensions.hashCode());
		return result;
	}

	public void setIssuer(String issuer)
	{
		this.issuer = issuer;
	}

	public void setPublicKey(PublicKey publicKey)
	{
		this.publicKey = publicKey;
	}

	public void setSerialNumber(BigInteger serialNumber)
	{
		this.serialNumber = serialNumber;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm)
	{
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public void setSubject(String subject)
	{
		this.subject = subject;
	}

	public void setValitidy(Valitidy valitidy)
	{
		this.valitidy = valitidy;
	}

	public void setVersion(int version)
	{
		this.version = version;
	}

	public void setX509v3Extensions(Map<String, String> x509v3Extensions)
	{
		this.x509v3Extensions = x509v3Extensions;
	}

	public CertificateInfoBuilder<?, ?> toBuilder()
	{
		return new CertificateInfoBuilderImpl().$fillValuesFrom(this);
	}

	public String toString()
	{
		return "CertificateInfo(version=" + this.getVersion() + ", serialNumber="
			+ this.getSerialNumber() + ", issuer=" + this.getIssuer() + ", subject="
			+ this.getSubject() + ", valitidy=" + this.getValitidy() + ", publicKey="
			+ this.getPublicKey() + ", signatureAlgorithm=" + this.getSignatureAlgorithm()
			+ ", x509v3Extensions=" + this.getX509v3Extensions() + ")";
	}
}
