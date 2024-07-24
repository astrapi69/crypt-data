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
package io.github.astrapi69.crypt.data.blockchain;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.api.blockchain.IAddress;
import io.github.astrapi69.crypt.data.hash.HashExtensions;

/**
 * The class {@link Address} represents a blockchain address, consisting of a name, a public key,
 * and a hash generated from these values using a specified hash algorithm.
 */
public class Address implements IAddress
{

	/** The hash of the address, generated from the name and public key. */
	private byte[] hash;

	/** The name of the address. */
	private String name;

	/** The public key associated with the address. */
	private byte[] publicKey;

	/**
	 * Instantiates a new {@link Address} with no parameters.
	 */
	public Address()
	{
	}

	/**
	 * Instantiates a new {@link Address} with the specified name and public key. The hash is
	 * automatically generated using the SHA-256 algorithm.
	 *
	 * @param name
	 *            the name of the address
	 * @param publicKey
	 *            the public key associated with the address
	 */
	public Address(String name, byte[] publicKey)
	{
		this.name = name;
		this.publicKey = publicKey;
		this.hash = HashExtensions.hash(name.getBytes(), publicKey, HashAlgorithm.SHA256);
	}

	/**
	 * Checks if the other object is an instance of {@link Address}.
	 *
	 * @param other
	 *            the other object to check
	 * @return true if the other object is an instance of {@link Address}, false otherwise
	 */
	protected boolean canEqual(final Object other)
	{
		return other instanceof Address;
	}


	/** {@inheritDoc} */
	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof Address))
			return false;
		final Address other = (Address)o;
		if (!other.canEqual(this))
			return false;
		if (!java.util.Arrays.equals(this.getHash(), other.getHash()))
			return false;
		final Object this$name = this.getName();
		final Object other$name = other.getName();
		if (this$name == null ? other$name != null : !this$name.equals(other$name))
			return false;
		return java.util.Arrays.equals(this.getPublicKey(), other.getPublicKey());
	}


	/** {@inheritDoc} */
	@Override
	public byte[] getHash()
	{
		return this.hash;
	}


	/** {@inheritDoc} */
	@Override
	public void setHash(byte[] hash)
	{
		this.hash = hash;
	}


	/** {@inheritDoc} */
	@Override
	public String getName()
	{
		return this.name;
	}


	/** {@inheritDoc} */
	@Override
	public void setName(String name)
	{
		this.name = name;
	}


	/** {@inheritDoc} */
	@Override
	public byte[] getPublicKey()
	{
		return this.publicKey;
	}


	/** {@inheritDoc} */
	@Override
	public void setPublicKey(byte[] publicKey)
	{
		this.publicKey = publicKey;
	}


	/** {@inheritDoc} */
	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		result = result * PRIME + java.util.Arrays.hashCode(this.getHash());
		final Object $name = this.getName();
		result = result * PRIME + ($name == null ? 43 : $name.hashCode());
		result = result * PRIME + java.util.Arrays.hashCode(this.getPublicKey());
		return result;
	}
}
