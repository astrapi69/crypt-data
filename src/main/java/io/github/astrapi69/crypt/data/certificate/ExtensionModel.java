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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;

import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;

/**
 * @deprecated use instead the class {@link io.github.astrapi69.crypt.data.model.ExtensionInfo}.
 *             Note will be removed in next minor version
 */
@Deprecated
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ExtensionModel
{
	private ASN1ObjectIdentifier extensionId;
	private boolean critical;
	private ASN1OctetString value;

	public ExtensionModel(ASN1ObjectIdentifier extensionId, boolean critical, ASN1OctetString value)
	{
		this.extensionId = extensionId;
		this.critical = critical;
		this.value = value;
	}

	public ExtensionModel()
	{
	}

	protected ExtensionModel(ExtensionInfoBuilder<?, ?> b)
	{
		this.extensionId = b.extensionId;
		this.critical = b.critical;
		this.value = b.value;
	}

	public static Extension toExtension(ExtensionModel extensionModel)
	{
		return new Extension(extensionModel.getExtensionId(), extensionModel.isCritical(),
			extensionModel.getValue());
	}

	public static ExtensionModel toExtensionInfo(Extension extension)
	{
		return ExtensionModel.builder().extensionId(extension.getExtnId())
			.critical(extension.isCritical()).value(extension.getExtnValue()).build();
	}

	public static ExtensionInfoBuilder<?, ?> builder()
	{
		return new ExtensionInfoBuilderImpl();
	}

	public ASN1ObjectIdentifier getExtensionId()
	{
		return this.extensionId;
	}

	public void setExtensionId(ASN1ObjectIdentifier extensionId)
	{
		this.extensionId = extensionId;
	}

	public boolean isCritical()
	{
		return this.critical;
	}

	public void setCritical(boolean critical)
	{
		this.critical = critical;
	}

	public ASN1OctetString getValue()
	{
		return this.value;
	}

	public void setValue(ASN1OctetString value)
	{
		this.value = value;
	}

	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof ExtensionModel))
			return false;
		final ExtensionModel other = (ExtensionModel)o;
		if (!other.canEqual((Object)this))
			return false;
		final Object this$extensionId = this.getExtensionId();
		final Object other$extensionId = other.getExtensionId();
		if (this$extensionId == null
			? other$extensionId != null
			: !this$extensionId.equals(other$extensionId))
			return false;
		if (this.isCritical() != other.isCritical())
			return false;
		final Object this$value = this.getValue();
		final Object other$value = other.getValue();
		if (this$value == null ? other$value != null : !this$value.equals(other$value))
			return false;
		return true;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof ExtensionModel;
	}

	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $extensionId = this.getExtensionId();
		result = result * PRIME + ($extensionId == null ? 43 : $extensionId.hashCode());
		result = result * PRIME + (this.isCritical() ? 79 : 97);
		final Object $value = this.getValue();
		result = result * PRIME + ($value == null ? 43 : $value.hashCode());
		return result;
	}

	public String toString()
	{
		return "ExtensionInfo(extensionId=" + this.getExtensionId() + ", critical="
			+ this.isCritical() + ", value=" + this.getValue() + ")";
	}

	public ExtensionInfoBuilder<?, ?> toBuilder()
	{
		return new ExtensionInfoBuilderImpl().$fillValuesFrom(this);
	}

	public static abstract class ExtensionInfoBuilder<C extends ExtensionModel, B extends ExtensionInfoBuilder<C, B>>
	{
		private ASN1ObjectIdentifier extensionId;
		private boolean critical;
		private ASN1OctetString value;

		private static void $fillValuesFromInstanceIntoBuilder(ExtensionModel instance,
			ExtensionInfoBuilder<?, ?> b)
		{
			b.extensionId(instance.extensionId);
			b.critical(instance.critical);
			b.value(instance.value);
		}

		public B extensionId(ASN1ObjectIdentifier extensionId)
		{
			this.extensionId = extensionId;
			return self();
		}

		public B critical(boolean critical)
		{
			this.critical = critical;
			return self();
		}

		public B value(ASN1OctetString value)
		{
			this.value = value;
			return self();
		}

		protected B $fillValuesFrom(C instance)
		{
			ExtensionInfoBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
			return self();
		}

		protected abstract B self();

		public abstract C build();

		public String toString()
		{
			return "ExtensionInfo.ExtensionInfoBuilder(extensionId=" + this.extensionId
				+ ", critical=" + this.critical + ", value=" + this.value + ")";
		}
	}

	private static final class ExtensionInfoBuilderImpl
		extends
			ExtensionInfoBuilder<ExtensionModel, ExtensionInfoBuilderImpl>
	{
		private ExtensionInfoBuilderImpl()
		{
		}

		protected ExtensionInfoBuilderImpl self()
		{
			return this;
		}

		public ExtensionModel build()
		{
			return new ExtensionModel(this);
		}
	}
}