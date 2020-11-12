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

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.blockchain.api.IBlock;
import de.alpharogroup.crypto.blockchain.api.ITransaction;
import de.alpharogroup.crypto.hash.HashExtensions;

/**
 * The class {@link Block}
 */
public class Block implements IBlock
{

	private byte[] hash;

	private byte[] merkleRoot;

	private byte[] previousBlockHash;

	private long timestamp;

	private List<ITransaction> transactions;

	private long tries;

	public Block()
	{
	}

	public Block(byte[] previousBlockHash, List<ITransaction> transactions, long tries)
	{
		this.previousBlockHash = previousBlockHash;
		this.transactions = transactions;
		this.tries = tries;
		this.timestamp = System.currentTimeMillis();
		this.merkleRoot = HashExtensions.getMerkleRootHash(
			new LinkedList<>(
				transactions.stream().map(ITransaction::getHash).collect(Collectors.toList())),
			HashAlgorithm.SHA256);
		this.hash = HashExtensions.hash(previousBlockHash, merkleRoot, tries, timestamp,
			HashAlgorithm.SHA256);
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof Block;
	}


	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof Block))
			return false;
		final Block other = (Block)o;
		if (!other.canEqual(this))
			return false;
		if (!java.util.Arrays.equals(this.getHash(), other.getHash()))
			return false;
		if (!java.util.Arrays.equals(this.getMerkleRoot(), other.getMerkleRoot()))
			return false;
		if (!java.util.Arrays.equals(this.getPreviousBlockHash(), other.getPreviousBlockHash()))
			return false;
		if (this.getTimestamp() != other.getTimestamp())
			return false;
		final Object this$transactions = this.getTransactions();
		final Object other$transactions = other.getTransactions();
		if (this$transactions == null
			? other$transactions != null
			: !this$transactions.equals(other$transactions))
			return false;
		if (this.getTries() != other.getTries())
			return false;
		return true;
	}

	@Override
	public byte[] getHash()
	{
		return this.hash;
	}

	@Override
	public int getLeadingZerosCount()
	{
		for (int i = 0; i < getHash().length; i++)
		{
			if (getHash()[i] != 0)
			{
				return i;
			}
		}
		return getHash().length;
	}

	@Override
	public byte[] getMerkleRoot()
	{
		return this.merkleRoot;
	}

	@Override
	public byte[] getPreviousBlockHash()
	{
		return this.previousBlockHash;
	}

	@Override
	public long getTimestamp()
	{
		return this.timestamp;
	}

	@Override
	public List<ITransaction> getTransactions()
	{
		return this.transactions;
	}

	@Override
	public long getTries()
	{
		return this.tries;
	}

	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		result = result * PRIME + java.util.Arrays.hashCode(this.getHash());
		result = result * PRIME + java.util.Arrays.hashCode(this.getMerkleRoot());
		result = result * PRIME + java.util.Arrays.hashCode(this.getPreviousBlockHash());
		final long $timestamp = this.getTimestamp();
		result = result * PRIME + (int)($timestamp >>> 32 ^ $timestamp);
		final Object $transactions = this.getTransactions();
		result = result * PRIME + ($transactions == null ? 43 : $transactions.hashCode());
		final long $tries = this.getTries();
		result = result * PRIME + (int)($tries >>> 32 ^ $tries);
		return result;
	}

	@Override
	public void setHash(byte[] hash)
	{
		this.hash = hash;
	}

	@Override
	public void setMerkleRoot(byte[] merkleRoot)
	{
		this.merkleRoot = merkleRoot;
	}

	@Override
	public void setPreviousBlockHash(byte[] previousBlockHash)
	{
		this.previousBlockHash = previousBlockHash;
	}

	@Override
	public void setTimestamp(long timestamp)
	{
		this.timestamp = timestamp;
	}

	@Override
	public void setTransactions(List<ITransaction> transactions)
	{
		this.transactions = transactions;
	}

	@Override
	public void setTries(long tries)
	{
		this.tries = tries;
	}
}
