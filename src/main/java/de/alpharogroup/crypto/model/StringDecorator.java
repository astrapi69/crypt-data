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

/**
 * The class {@link CharacterDecorator} that can decorate an crypt object with a {@link String} in
 * prefix and suffix
 */
public final class StringDecorator extends CryptObjectDecorator<String>
{
	public static abstract class StringDecoratorBuilder<C extends StringDecorator, B extends StringDecoratorBuilder<C, B>>
		extends
			CryptObjectDecorator.CryptObjectDecoratorBuilder<String, C, B>
	{
		@Override
		public abstract C build();

		@Override
		protected abstract B self();

		@Override
		public String toString()
		{
			return "StringDecorator.StringDecoratorBuilder(super=" + super.toString() + ")";
		}
	}

	private static final class StringDecoratorBuilderImpl
		extends
			StringDecoratorBuilder<StringDecorator, StringDecoratorBuilderImpl>
	{
		private StringDecoratorBuilderImpl()
		{
		}

		@Override
		public StringDecorator build()
		{
			return new StringDecorator(this);
		}

		@Override
		protected StringDecorator.StringDecoratorBuilderImpl self()
		{
			return this;
		}
	}

	public static StringDecoratorBuilder<?, ?> builder()
	{
		return new StringDecoratorBuilderImpl();
	}

	protected StringDecorator(StringDecoratorBuilder<?, ?> b)
	{
		super(b);
	}
}
