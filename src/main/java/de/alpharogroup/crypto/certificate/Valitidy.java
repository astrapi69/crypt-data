package de.alpharogroup.crypto.certificate;

import java.time.ZonedDateTime;

/**
 * Use only ZoneId.of("UTC") for the values
 **/
public class Valitidy
{
	private ZonedDateTime notBefore;
	private ZonedDateTime notAfter;

	public Valitidy(ZonedDateTime notBefore, ZonedDateTime notAfter) {
		this.notBefore = notBefore;
		this.notAfter = notAfter;
	}

	public Valitidy() {
	}

	protected Valitidy(ValitidyBuilder<?, ?> b) {
		this.notBefore = b.notBefore;
		this.notAfter = b.notAfter;
	}

	public static ValitidyBuilder<?, ?> builder() {
		return new ValitidyBuilderImpl();
	}

	public ZonedDateTime getNotBefore() {
		return this.notBefore;
	}

	public ZonedDateTime getNotAfter() {
		return this.notAfter;
	}

	public void setNotBefore(ZonedDateTime notBefore) {
		this.notBefore = notBefore;
	}

	public void setNotAfter(ZonedDateTime notAfter) {
		this.notAfter = notAfter;
	}

	public boolean equals(final Object o) {
		if (o == this) return true;
		if (!(o instanceof Valitidy)) return false;
		final Valitidy other = (Valitidy) o;
		if (!other.canEqual((Object) this)) return false;
		final Object this$notBefore = this.getNotBefore();
		final Object other$notBefore = other.getNotBefore();
		if (this$notBefore == null ? other$notBefore != null : !this$notBefore.equals(other$notBefore)) return false;
		final Object this$notAfter = this.getNotAfter();
		final Object other$notAfter = other.getNotAfter();
		if (this$notAfter == null ? other$notAfter != null : !this$notAfter.equals(other$notAfter)) return false;
		return true;
	}

	protected boolean canEqual(final Object other) {
		return other instanceof Valitidy;
	}

	public int hashCode() {
		final int PRIME = 59;
		int result = 1;
		final Object $notBefore = this.getNotBefore();
		result = result * PRIME + ($notBefore == null ? 43 : $notBefore.hashCode());
		final Object $notAfter = this.getNotAfter();
		result = result * PRIME + ($notAfter == null ? 43 : $notAfter.hashCode());
		return result;
	}

	public String toString() {
		return "Valitidy(notBefore=" + this.getNotBefore() + ", notAfter=" + this.getNotAfter() + ")";
	}

	public ValitidyBuilder<?, ?> toBuilder() {
		return new ValitidyBuilderImpl().$fillValuesFrom(this);
	}

	public static abstract class ValitidyBuilder<C extends Valitidy, B extends Valitidy.ValitidyBuilder<C, B>> {
		private ZonedDateTime notBefore;
		private ZonedDateTime notAfter;

		private static void $fillValuesFromInstanceIntoBuilder(Valitidy instance, Valitidy.ValitidyBuilder<?, ?> b) {
			b.notBefore(instance.notBefore);
			b.notAfter(instance.notAfter);
		}

		public B notBefore(ZonedDateTime notBefore) {
			this.notBefore = notBefore;
			return self();
		}

		public B notAfter(ZonedDateTime notAfter) {
			this.notAfter = notAfter;
			return self();
		}

		protected B $fillValuesFrom(C instance) {
			ValitidyBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
			return self();
		}

		protected abstract B self();

		public abstract C build();

		public String toString() {
			return "Valitidy.ValitidyBuilder(notBefore=" + this.notBefore + ", notAfter=" + this.notAfter + ")";
		}
	}

	private static final class ValitidyBuilderImpl extends ValitidyBuilder<Valitidy, ValitidyBuilderImpl> {
		private ValitidyBuilderImpl() {
		}

		protected Valitidy.ValitidyBuilderImpl self() {
			return this;
		}

		public Valitidy build() {
			return new Valitidy(this);
		}
	}
}

