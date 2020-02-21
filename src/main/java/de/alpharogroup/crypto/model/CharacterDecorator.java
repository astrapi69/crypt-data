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
 * The class {@link CharacterDecorator} that can decorate an crypt object with a {@link Character}
 * in prefix and suffix
 */
public final class CharacterDecorator extends CryptObjectDecorator<Character>
{
	public static abstract class CharacterDecoratorBuilder<C extends CharacterDecorator, B extends CharacterDecoratorBuilder<C, B>>
		extends
			CryptObjectDecorator.CryptObjectDecoratorBuilder<Character, C, B>
	{
		@Override
		public abstract C build();

		@Override
		protected abstract B self();

		@Override
		public String toString()
		{
			return "CharacterDecorator.CharacterDecoratorBuilder(super=" + super.toString() + ")";
		}
	}

	private static final class CharacterDecoratorBuilderImpl
		extends
			CharacterDecoratorBuilder<CharacterDecorator, CharacterDecoratorBuilderImpl>
	{
		private CharacterDecoratorBuilderImpl()
		{
		}

		@Override
		public CharacterDecorator build()
		{
			return new CharacterDecorator(this);
		}

		@Override
		protected CharacterDecorator.CharacterDecoratorBuilderImpl self()
		{
			return this;
		}
	}

	public static CharacterDecoratorBuilder<?, ?> builder()
	{
		return new CharacterDecoratorBuilderImpl();
	}

	protected CharacterDecorator(CharacterDecoratorBuilder<?, ?> b)
	{
		super(b);
	}
}
