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

import de.alpharogroup.crypto.algorithm.Algorithm;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * The class {@link CryptModel} holds data for the encryption or decryption process.
 *
 * @param <C>
 *            the generic type of the cipher
 * @param <K>
 *            the generic type of the key
 */
public class CryptModel<C, K, T> implements Serializable
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The algorithm. */
	private Algorithm algorithm;

	/** The cipher. */
	private C cipher;

	/** The decorators for the crypt object */
	private List<CryptObjectDecorator<T>> decorators;

	/**
	 * The flag initialized that indicates if the cipher is initialized.
	 */
	private boolean initialized;

	/** The iteration count. */
	private Integer iterationCount;

	/** The key. */
	private K key;

	/** The operation mode that indicates if an encryption or decryption process will start. */
	private int operationMode;

	/** The salt byte array. */
	private byte[] salt;

	public CryptModel(Algorithm algorithm, C cipher, List<CryptObjectDecorator<T>> decorators,
		boolean initialized, Integer iterationCount, K key, int operationMode, byte[] salt)
	{
		this.algorithm = algorithm;
		this.cipher = cipher;
		this.decorators = decorators;
		this.initialized = initialized;
		this.iterationCount = iterationCount;
		this.key = key;
		this.operationMode = operationMode;
		this.salt = salt;
	}

	public CryptModel()
	{
	}

	protected CryptModel(CryptModelBuilder<C, K, T, ?, ?> b)
	{
		this.algorithm = b.algorithm;
		this.cipher = b.cipher;
		List<CryptObjectDecorator<T>> decorators;
		switch (b.decorators == null ? 0 : b.decorators.size())
		{
			case 0:
				decorators = java.util.Collections.emptyList();
				break;
			case 1:
				decorators = java.util.Collections.singletonList(b.decorators.get(0));
				break;
			default:
				decorators = java.util.Collections
					.unmodifiableList(new ArrayList<CryptObjectDecorator<T>>(b.decorators));
		}
		this.decorators = decorators;
		this.initialized = b.initialized;
		this.iterationCount = b.iterationCount;
		this.key = b.key;
		this.operationMode = b.operationMode;
		this.salt = b.salt;
	}

	public static <C, K, T> CryptModelBuilder<C, K, T, ?, ?> builder()
	{
		return new CryptModelBuilderImpl<C, K, T>();
	}

	public Algorithm getAlgorithm()
	{
		return this.algorithm;
	}

	public C getCipher()
	{
		return this.cipher;
	}

	public List<CryptObjectDecorator<T>> getDecorators()
	{
		return this.decorators;
	}

	public boolean isInitialized()
	{
		return this.initialized;
	}

	public Integer getIterationCount()
	{
		return this.iterationCount;
	}

	public K getKey()
	{
		return this.key;
	}

	public int getOperationMode()
	{
		return this.operationMode;
	}

	public byte[] getSalt()
	{
		return this.salt;
	}

	public void setAlgorithm(Algorithm algorithm)
	{
		this.algorithm = algorithm;
	}

	public void setCipher(C cipher)
	{
		this.cipher = cipher;
	}

	public void setDecorators(List<CryptObjectDecorator<T>> decorators)
	{
		this.decorators = decorators;
	}

	public void setInitialized(boolean initialized)
	{
		this.initialized = initialized;
	}

	public void setIterationCount(Integer iterationCount)
	{
		this.iterationCount = iterationCount;
	}

	public void setKey(K key)
	{
		this.key = key;
	}

	public void setOperationMode(int operationMode)
	{
		this.operationMode = operationMode;
	}

	public void setSalt(byte[] salt)
	{
		this.salt = salt;
	}

	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof CryptModel))
			return false;
		final CryptModel<?, ?, ?> other = (CryptModel<?, ?, ?>)o;
		if (!other.canEqual((Object)this))
			return false;
		final Object this$algorithm = this.getAlgorithm();
		final Object other$algorithm = other.getAlgorithm();
		if (this$algorithm == null ?
			other$algorithm != null :
			!this$algorithm.equals(other$algorithm))
			return false;
		final Object this$cipher = this.getCipher();
		final Object other$cipher = other.getCipher();
		if (this$cipher == null ? other$cipher != null : !this$cipher.equals(other$cipher))
			return false;
		final Object this$decorators = this.getDecorators();
		final Object other$decorators = other.getDecorators();
		if (this$decorators == null ?
			other$decorators != null :
			!this$decorators.equals(other$decorators))
			return false;
		if (this.isInitialized() != other.isInitialized())
			return false;
		final Object this$iterationCount = this.getIterationCount();
		final Object other$iterationCount = other.getIterationCount();
		if (this$iterationCount == null ?
			other$iterationCount != null :
			!this$iterationCount.equals(other$iterationCount))
			return false;
		final Object this$key = this.getKey();
		final Object other$key = other.getKey();
		if (this$key == null ? other$key != null : !this$key.equals(other$key))
			return false;
		if (this.getOperationMode() != other.getOperationMode())
			return false;
		if (!java.util.Arrays.equals(this.getSalt(), other.getSalt()))
			return false;
		return true;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof CryptModel;
	}

	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $algorithm = this.getAlgorithm();
		result = result * PRIME + ($algorithm == null ? 43 : $algorithm.hashCode());
		final Object $cipher = this.getCipher();
		result = result * PRIME + ($cipher == null ? 43 : $cipher.hashCode());
		final Object $decorators = this.getDecorators();
		result = result * PRIME + ($decorators == null ? 43 : $decorators.hashCode());
		result = result * PRIME + (this.isInitialized() ? 79 : 97);
		final Object $iterationCount = this.getIterationCount();
		result = result * PRIME + ($iterationCount == null ? 43 : $iterationCount.hashCode());
		final Object $key = this.getKey();
		result = result * PRIME + ($key == null ? 43 : $key.hashCode());
		result = result * PRIME + this.getOperationMode();
		result = result * PRIME + java.util.Arrays.hashCode(this.getSalt());
		return result;
	}

	public String toString()
	{
		return "CryptModel(algorithm=" + this.getAlgorithm() + ", cipher=" + this.getCipher()
			+ ", decorators=" + this.getDecorators() + ", initialized=" + this.isInitialized()
			+ ", iterationCount=" + this.getIterationCount() + ", key=" + this.getKey()
			+ ", operationMode=" + this.getOperationMode() + ", salt=" + java.util.Arrays
			.toString(this.getSalt()) + ")";
	}

	public CryptModelBuilder<C, K, T, ?, ?> toBuilder()
	{
		return new CryptModelBuilderImpl<C, K, T>().$fillValuesFrom(this);
	}

	public static abstract class CryptModelBuilder<C, K, T, C2 extends CryptModel<C, K, T>, B extends CryptModel.CryptModelBuilder<C, K, T, C2, B>>
	{
		private Algorithm algorithm;
		private C cipher;
		private ArrayList<CryptObjectDecorator<T>> decorators;
		private boolean initialized;
		private Integer iterationCount;
		private K key;
		private int operationMode;
		private byte[] salt;

		private static <C, K, T> void $fillValuesFromInstanceIntoBuilder(
			CryptModel<C, K, T> instance, CryptModel.CryptModelBuilder<C, K, T, ?, ?> b)
		{
			b.algorithm(instance.algorithm);
			b.cipher(instance.cipher);
			b.decorators(instance.decorators == null ?
				java.util.Collections.emptyList() :
				instance.decorators);
			b.initialized(instance.initialized);
			b.iterationCount(instance.iterationCount);
			b.key(instance.key);
			b.operationMode(instance.operationMode);
			b.salt(instance.salt);
		}

		public B algorithm(Algorithm algorithm)
		{
			this.algorithm = algorithm;
			return self();
		}

		public B cipher(C cipher)
		{
			this.cipher = cipher;
			return self();
		}

		public B decorator(CryptObjectDecorator<T> decorator)
		{
			if (this.decorators == null)
				this.decorators = new ArrayList<CryptObjectDecorator<T>>();
			this.decorators.add(decorator);
			return self();
		}

		public B decorators(Collection<? extends CryptObjectDecorator<T>> decorators)
		{
			if (this.decorators == null)
				this.decorators = new ArrayList<CryptObjectDecorator<T>>();
			this.decorators.addAll(decorators);
			return self();
		}

		public B clearDecorators()
		{
			if (this.decorators != null)
				this.decorators.clear();
			return self();
		}

		public B initialized(boolean initialized)
		{
			this.initialized = initialized;
			return self();
		}

		public B iterationCount(Integer iterationCount)
		{
			this.iterationCount = iterationCount;
			return self();
		}

		public B key(K key)
		{
			this.key = key;
			return self();
		}

		public B operationMode(int operationMode)
		{
			this.operationMode = operationMode;
			return self();
		}

		public B salt(byte[] salt)
		{
			this.salt = salt;
			return self();
		}

		protected B $fillValuesFrom(C2 instance)
		{
			CryptModelBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
			return self();
		}

		protected abstract B self();

		public abstract C2 build();

		public String toString()
		{
			return "CryptModel.CryptModelBuilder(algorithm=" + this.algorithm + ", cipher="
				+ this.cipher + ", decorators=" + this.decorators + ", initialized="
				+ this.initialized + ", iterationCount=" + this.iterationCount + ", key=" + this.key
				+ ", operationMode=" + this.operationMode + ", salt=" + java.util.Arrays
				.toString(this.salt) + ")";
		}
	}

	private static final class CryptModelBuilderImpl<C, K, T>
		extends CryptModelBuilder<C, K, T, CryptModel<C, K, T>, CryptModelBuilderImpl<C, K, T>>
	{
		private CryptModelBuilderImpl()
		{
		}

		protected CryptModel.CryptModelBuilderImpl<C, K, T> self()
		{
			return this;
		}

		public CryptModel<C, K, T> build()
		{
			return new CryptModel<C, K, T>(this);
		}
	}
}
