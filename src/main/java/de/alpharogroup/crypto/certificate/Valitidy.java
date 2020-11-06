package de.alpharogroup.crypto.certificate;

import java.time.ZonedDateTime;

/**
 * Use only ZoneId.of("UTC") for the values
 **/
public class Valitidy
{
	public static abstract class ValitidyBuilder<C extends Valitidy, B extends Valitidy.ValitidyBuilder<C, B>>
	{
		private static void $fillValuesFromInstanceIntoBuilder(Valitidy instance,
			Valitidy.ValitidyBuilder<?, ?> b)
		{
			b.notBefore(instance.notBefore);
			b.notAfter(instance.notAfter);
		}
		private ZonedDateTime notAfter;

		private ZonedDateTime notBefore;

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

		public Valitidy build()
		{
			return new Valitidy(this);
		}

		protected Valitidy.ValitidyBuilderImpl self()
		{
			return this;
		}
	}

	public static ValitidyBuilder<?, ?> builder()
	{
		return new ValitidyBuilderImpl();
	}

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

	protected boolean canEqual(final Object other)
	{
		return other instanceof Valitidy;
	}

	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof Valitidy))
			return false;
		final Valitidy other = (Valitidy)o;
		if (!other.canEqual((Object)this))
			return false;
		final Object this$notBefore = this.getNotBefore();
		final Object other$notBefore = other.getNotBefore();
		if (this$notBefore == null
			? other$notBefore != null
			: !this$notBefore.equals(other$notBefore))
			return false;
		final Object this$notAfter = this.getNotAfter();
		final Object other$notAfter = other.getNotAfter();
		if (this$notAfter == null ? other$notAfter != null : !this$notAfter.equals(other$notAfter))
			return false;
		return true;
	}

	public ZonedDateTime getNotAfter()
	{
		return this.notAfter;
	}

	public ZonedDateTime getNotBefore()
	{
		return this.notBefore;
	}

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

	public void setNotAfter(ZonedDateTime notAfter)
	{
		this.notAfter = notAfter;
	}

	public void setNotBefore(ZonedDateTime notBefore)
	{
		this.notBefore = notBefore;
	}

	public ValitidyBuilder<?, ?> toBuilder()
	{
		return new ValitidyBuilderImpl().$fillValuesFrom(this);
	}

	public String toString()
	{
		return "Valitidy(notBefore=" + this.getNotBefore() + ", notAfter=" + this.getNotAfter()
			+ ")";
	}
}

