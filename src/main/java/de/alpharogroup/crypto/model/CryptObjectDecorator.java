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
package de.alpharogroup.crypto.model;

import java.util.Objects;

/**
 * The class {@link CryptObjectDecorator} holds a prefix and a suffix that can decorate an crypt
 * object
 *
 * @param <T>
 *            the generic type of the prefix and the suffix
 */
public class CryptObjectDecorator<T>
{

	/** The prefix for the crypt object */
	private final T prefix;

	/** The suffix for the crypt object */
	private final T suffix;

	protected CryptObjectDecorator(CryptObjectDecoratorBuilder<T, ?, ?> b)
	{
		Objects.requireNonNull(b);
		Objects.requireNonNull(b.prefix);
		Objects.requireNonNull(b.suffix);
		this.prefix = b.prefix;
		this.suffix = b.suffix;
	}

	public static <T> CryptObjectDecoratorBuilder<T, ?, ?> builder()
	{
		return new CryptObjectDecoratorBuilderImpl<T>();
	}

	public T getPrefix()
	{
		return this.prefix;
	}

	public T getSuffix()
	{
		return this.suffix;
	}

	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof CryptObjectDecorator))
			return false;
		final CryptObjectDecorator<?> other = (CryptObjectDecorator<?>)o;
		if (!other.canEqual((Object)this))
			return false;
		final Object this$prefix = this.getPrefix();
		final Object other$prefix = other.getPrefix();
		if (this$prefix == null ? other$prefix != null : !this$prefix.equals(other$prefix))
			return false;
		final Object this$suffix = this.getSuffix();
		final Object other$suffix = other.getSuffix();
		if (this$suffix == null ? other$suffix != null : !this$suffix.equals(other$suffix))
			return false;
		return true;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof CryptObjectDecorator;
	}

	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $prefix = this.getPrefix();
		result = result * PRIME + ($prefix == null ? 43 : $prefix.hashCode());
		final Object $suffix = this.getSuffix();
		result = result * PRIME + ($suffix == null ? 43 : $suffix.hashCode());
		return result;
	}

	public String toString()
	{
		return "CryptObjectDecorator(prefix=" + this.getPrefix() + ", suffix=" + this.getSuffix()
			+ ")";
	}

	public static abstract class CryptObjectDecoratorBuilder<T, C extends CryptObjectDecorator<T>, B extends CryptObjectDecorator.CryptObjectDecoratorBuilder<T, C, B>>
	{
		private T prefix;
		private T suffix;

		public B prefix(T prefix)
		{
			Objects.requireNonNull(prefix);
			this.prefix = prefix;
			return self();
		}

		public B suffix(T suffix)
		{
			Objects.requireNonNull(suffix);
			this.suffix = suffix;
			return self();
		}

		protected abstract B self();

		public abstract C build();

		public String toString()
		{
			return "CryptObjectDecorator.CryptObjectDecoratorBuilder(prefix=" + this.prefix
				+ ", suffix=" + this.suffix + ")";
		}
	}

	private static final class CryptObjectDecoratorBuilderImpl<T>
		extends CryptObjectDecoratorBuilder<T, CryptObjectDecorator<T>, CryptObjectDecoratorBuilderImpl<T>>
	{
		private CryptObjectDecoratorBuilderImpl()
		{
		}

		protected CryptObjectDecorator.CryptObjectDecoratorBuilderImpl<T> self()
		{
			return this;
		}

		public CryptObjectDecorator<T> build()
		{
			return new CryptObjectDecorator<T>(this);
		}
	}
}
