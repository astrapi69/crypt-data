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

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.api.blockchain.IBlock;
import io.github.astrapi69.crypt.api.blockchain.ITransaction;
import io.github.astrapi69.crypt.data.hash.HashExtensions;

/**
 * The class {@link Block} represents a block in a blockchain. It contains the current block's hash,
 * the previous block's hash, the Merkle root of the transactions, a timestamp, a list of
 * transactions, a data field, and the number of attempts (tries) to find a valid hash.
 */
public class Block implements IBlock
{

	/**
	 * The hash of the block, generated from the previous block hash, Merkle root, tries, and
	 * timestamp.
	 */
	private byte[] hash;

	/** The Merkle root of the block's transactions. */
	private byte[] merkleRoot;

	/** The hash of the previous block in the blockchain. */
	private byte[] previousBlockHash;

	/** The timestamp when the block was created. */
	private long timestamp;

	/** The list of transactions included in the block. */
	private List<ITransaction> transactions;

	/** The number of attempts to find a valid hash. */
	private long tries;

	/** The data field for additional information in the block. */
	private String data;

	/**
	 * Instantiates a new {@link Block} with no parameters.
	 */
	public Block()
	{
	}

	/**
	 * Instantiates a new {@link Block} with the specified previous block hash, list of
	 * transactions, and tries. The Merkle root and hash are automatically generated using the
	 * SHA-256 algorithm.
	 *
	 * @param previousBlockHash
	 *            the hash of the previous block
	 * @param transactions
	 *            the list of transactions included in the block
	 * @param tries
	 *            the number of attempts to find a valid hash
	 */
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

	/**
	 * Checks if the other object is an instance of {@link Block}.
	 *
	 * @param other
	 *            the other object to check
	 * @return true if the other object is an instance of {@link Block}, false otherwise
	 */
	protected boolean canEqual(final Object other)
	{
		return other instanceof Block;
	}

	/**
	 * {@inheritDoc}
	 */
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
		return this.getTries() == other.getTries();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] getHash()
	{
		return this.hash;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setHash(byte[] hash)
	{
		this.hash = hash;
	}

	/**
	 * {@inheritDoc}
	 */
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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] getMerkleRoot()
	{
		return this.merkleRoot;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setMerkleRoot(byte[] merkleRoot)
	{
		this.merkleRoot = merkleRoot;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] getPreviousBlockHash()
	{
		return this.previousBlockHash;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setPreviousBlockHash(byte[] previousBlockHash)
	{
		this.previousBlockHash = previousBlockHash;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long getTimestamp()
	{
		return this.timestamp;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setTimestamp(long timestamp)
	{
		this.timestamp = timestamp;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<ITransaction> getTransactions()
	{
		return this.transactions;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setTransactions(List<ITransaction> transactions)
	{
		this.transactions = transactions;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long getTries()
	{
		return this.tries;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setTries(long tries)
	{
		this.tries = tries;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getData()
	{
		return this.data;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setData(String data)
	{
		this.data = data;
	}

	/**
	 * {@inheritDoc}
	 */
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
}
