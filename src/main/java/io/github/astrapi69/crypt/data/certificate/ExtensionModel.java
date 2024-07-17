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
 * The type Extension model.
 *
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

	/**
	 * Instantiates a new Extension model.
	 *
	 * @param extensionId
	 *            the extension id
	 * @param critical
	 *            the critical
	 * @param value
	 *            the value
	 */
	public ExtensionModel(ASN1ObjectIdentifier extensionId, boolean critical, ASN1OctetString value)
	{
		this.extensionId = extensionId;
		this.critical = critical;
		this.value = value;
	}

	/**
	 * Instantiates a new Extension model.
	 */
	public ExtensionModel()
	{
	}

	/**
	 * Instantiates a new Extension model.
	 *
	 * @param b
	 *            the b
	 */
	protected ExtensionModel(ExtensionInfoBuilder<?, ?> b)
	{
		this.extensionId = b.extensionId;
		this.critical = b.critical;
		this.value = b.value;
	}

	/**
	 * To extension extension.
	 *
	 * @param extensionModel
	 *            the extension model
	 * @return the extension
	 */
	public static Extension toExtension(ExtensionModel extensionModel)
	{
		return new Extension(extensionModel.getExtensionId(), extensionModel.isCritical(),
			extensionModel.getValue());
	}

	/**
	 * To extension info extension model.
	 *
	 * @param extension
	 *            the extension
	 * @return the extension model
	 */
	public static ExtensionModel toExtensionInfo(Extension extension)
	{
		return ExtensionModel.builder().extensionId(extension.getExtnId())
			.critical(extension.isCritical()).value(extension.getExtnValue()).build();
	}

	/**
	 * Builder extension info builder.
	 *
	 * @return the extension info builder
	 */
	public static ExtensionInfoBuilder<?, ?> builder()
	{
		return new ExtensionInfoBuilderImpl();
	}

	/**
	 * Gets extension id.
	 *
	 * @return the extension id
	 */
	public ASN1ObjectIdentifier getExtensionId()
	{
		return this.extensionId;
	}

	/**
	 * Sets extension id.
	 *
	 * @param extensionId
	 *            the extension id
	 */
	public void setExtensionId(ASN1ObjectIdentifier extensionId)
	{
		this.extensionId = extensionId;
	}

	/**
	 * Is critical boolean.
	 *
	 * @return the boolean
	 */
	public boolean isCritical()
	{
		return this.critical;
	}

	/**
	 * Sets critical.
	 *
	 * @param critical
	 *            the critical
	 */
	public void setCritical(boolean critical)
	{
		this.critical = critical;
	}

	/**
	 * Gets value.
	 *
	 * @return the value
	 */
	public ASN1OctetString getValue()
	{
		return this.value;
	}

	/**
	 * Sets value.
	 *
	 * @param value
	 *            the value
	 */
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

	/**
	 * Can equal boolean.
	 *
	 * @param other
	 *            the other
	 * @return the boolean
	 */
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

	/**
	 * To builder extension info builder.
	 *
	 * @return the extension info builder
	 */
	public ExtensionInfoBuilder<?, ?> toBuilder()
	{
		return new ExtensionInfoBuilderImpl().$fillValuesFrom(this);
	}

	/**
	 * The type Extension info builder.
	 *
	 * @param <C>
	 *            the type parameter
	 * @param <B>
	 *            the type parameter
	 */
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

		/**
		 * Extension id b.
		 *
		 * @param extensionId
		 *            the extension id
		 * @return the b
		 */
		public B extensionId(ASN1ObjectIdentifier extensionId)
		{
			this.extensionId = extensionId;
			return self();
		}

		/**
		 * Critical b.
		 *
		 * @param critical
		 *            the critical
		 * @return the b
		 */
		public B critical(boolean critical)
		{
			this.critical = critical;
			return self();
		}

		/**
		 * Value b.
		 *
		 * @param value
		 *            the value
		 * @return the b
		 */
		public B value(ASN1OctetString value)
		{
			this.value = value;
			return self();
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
			ExtensionInfoBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
			return self();
		}

		/**
		 * Self b.
		 *
		 * @return the b
		 */
		protected abstract B self();

		/**
		 * Build c.
		 *
		 * @return the c
		 */
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
