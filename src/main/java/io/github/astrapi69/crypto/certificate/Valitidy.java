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
package io.github.astrapi69.crypto.certificate;

import java.time.ZonedDateTime;

/**
 * Use only ZoneId.of("UTC") for the values
 **/
public class Valitidy
{
	private ZonedDateTime notAfter;
	private ZonedDateTime notBefore;

	public Valitidy()
	{
	}

	protected Valitidy(ValitidyBuilder<?, ?> b)
	{
		this.notBefore = b.notBefore;
		this.notAfter = b.notAfter;
	}

	public Valitidy(ZonedDateTime notBefore, ZonedDateTime notAfter)
	{
		this.notBefore = notBefore;
		this.notAfter = notAfter;
	}

	public static ValitidyBuilder<?, ?> builder()
	{
		return new ValitidyBuilderImpl();
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof Valitidy;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof Valitidy))
			return false;
		final Valitidy other = (Valitidy)o;
		if (!other.canEqual(this))
			return false;
		final Object this$notBefore = this.getNotBefore();
		final Object other$notBefore = other.getNotBefore();
		if (this$notBefore == null
			? other$notBefore != null
			: !this$notBefore.equals(other$notBefore))
			return false;
		final Object this$notAfter = this.getNotAfter();
		final Object other$notAfter = other.getNotAfter();
		return this$notAfter == null
			? other$notAfter == null
			: this$notAfter.equals(other$notAfter);
	}

	public ZonedDateTime getNotAfter()
	{
		return this.notAfter;
	}

	public void setNotAfter(ZonedDateTime notAfter)
	{
		this.notAfter = notAfter;
	}

	public ZonedDateTime getNotBefore()
	{
		return this.notBefore;
	}

	public void setNotBefore(ZonedDateTime notBefore)
	{
		this.notBefore = notBefore;
	}

	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $notBefore = this.getNotBefore();
		result = result * PRIME + ($notBefore == null ? 43 : $notBefore.hashCode());
		final Object $notAfter = this.getNotAfter();
		result = result * PRIME + ($notAfter == null ? 43 : $notAfter.hashCode());
		return result;
	}

	public ValitidyBuilder<?, ?> toBuilder()
	{
		return new ValitidyBuilderImpl().$fillValuesFrom(this);
	}

	@Override
	public String toString()
	{
		return "Valitidy(notBefore=" + this.getNotBefore() + ", notAfter=" + this.getNotAfter()
			+ ")";
	}

	public static abstract class ValitidyBuilder<C extends Valitidy, B extends Valitidy.ValitidyBuilder<C, B>>
	{
		private ZonedDateTime notAfter;
		private ZonedDateTime notBefore;

		private static void $fillValuesFromInstanceIntoBuilder(Valitidy instance,
			Valitidy.ValitidyBuilder<?, ?> b)
		{
			b.notBefore(instance.notBefore);
			b.notAfter(instance.notAfter);
		}

		protected B $fillValuesFrom(C instance)
		{
			ValitidyBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
			return self();
		}

		public abstract C build();

		public B notAfter(ZonedDateTime notAfter)
		{
			this.notAfter = notAfter;
			return self();
		}

		public B notBefore(ZonedDateTime notBefore)
		{
			this.notBefore = notBefore;
			return self();
		}

		protected abstract B self();

		@Override
		public String toString()
		{
			return "Valitidy.ValitidyBuilder(notBefore=" + this.notBefore + ", notAfter="
				+ this.notAfter + ")";
		}
	}

	private static final class ValitidyBuilderImpl
		extends
			ValitidyBuilder<Valitidy, ValitidyBuilderImpl>
	{
		private ValitidyBuilderImpl()
		{
		}

		@Override
		public Valitidy build()
		{
			return new Valitidy(this);
		}

		@Override
		protected Valitidy.ValitidyBuilderImpl self()
		{
			return this;
		}
	}
}

