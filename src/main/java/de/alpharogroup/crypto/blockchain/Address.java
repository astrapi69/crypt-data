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
package de.alpharogroup.crypto.blockchain;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.blockchain.api.IAddress;
import de.alpharogroup.crypto.hash.HashExtensions;

/**
 * The class {@link Address}
 */
public class Address implements IAddress
{

	/** The hash. */
	private byte[] hash;

	/** The name. */
	private String name;

	/** The public key. */
	private byte[] publicKey;

	/**
	 * Instantiates a new {@link Address}
	 *
	 * @param name
	 *            the name
	 * @param publicKey
	 *            the public key
	 */
	public Address(String name, byte[] publicKey)
	{
		this.name = name;
		this.publicKey = publicKey;
		this.hash = HashExtensions.hash(name.getBytes(), publicKey, HashAlgorithm.SHA256);
	}

	public Address()
	{
	}

	public byte[] getHash()
	{
		return this.hash;
	}

	public String getName()
	{
		return this.name;
	}

	public byte[] getPublicKey()
	{
		return this.publicKey;
	}

	public void setHash(byte[] hash)
	{
		this.hash = hash;
	}

	public void setName(String name)
	{
		this.name = name;
	}

	public void setPublicKey(byte[] publicKey)
	{
		this.publicKey = publicKey;
	}

	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof Address))
			return false;
		final Address other = (Address)o;
		if (!other.canEqual((Object)this))
			return false;
		if (!java.util.Arrays.equals(this.getHash(), other.getHash()))
			return false;
		final Object this$name = this.getName();
		final Object other$name = other.getName();
		if (this$name == null ? other$name != null : !this$name.equals(other$name))
			return false;
		if (!java.util.Arrays.equals(this.getPublicKey(), other.getPublicKey()))
			return false;
		return true;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof Address;
	}

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
