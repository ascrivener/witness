// SPDX-License-Identifier: Apache-2.0
// Toy contracts for measuring the evm-bounty check. None of them is deployed anywhere: the
// evm-report tool writes their runtime code and storage straight into synthetic state.
// Compile with solc 0.8.28 (`scripts/evm-report-contracts.sh` writes the *.hex next to this).
pragma solidity 0.8.28;

/// A bare token, wrapping ETH 1:1 as WETH does. Slots: balanceOf 0, allowance 1, totalSupply 2.
contract Token {
	mapping(address => uint256) public balanceOf;
	mapping(address => mapping(address => uint256)) public allowance;
	uint256 public totalSupply;

	function deposit() external payable {
		balanceOf[msg.sender] += msg.value;
		totalSupply += msg.value;
	}

	function transfer(address to, uint256 value) external returns (bool) {
		balanceOf[msg.sender] -= value;
		balanceOf[to] += value;
		return true;
	}

	function transferFrom(address from, address to, uint256 value) external returns (bool) {
		allowance[from][msg.sender] -= value;
		balanceOf[from] -= value;
		balanceOf[to] += value;
		return true;
	}

	function approve(address spender, uint256 value) external returns (bool) {
		allowance[msg.sender][spender] = value;
		return true;
	}
}

/// A constant-product pair with a 0.3% fee, and a planted bug: `swap` checks the fee-adjusted
/// product at the wrong scale, so a swap can take almost all of one reserve for 1 wei of the
/// other. Slots: token0 0, token1 1, reserve0 2, reserve1 3.
contract Pair {
	Token public token0;
	Token public token1;
	uint256 public reserve0;
	uint256 public reserve1;

	function getReserves() external view returns (uint256, uint256) {
		return (reserve0, reserve1);
	}

	/// Send `out0` and `out1` to `to`, having been paid in first, as Uniswap V2's pairs do.
	function swap(uint256 out0, uint256 out1, address to) external {
		(uint256 r0, uint256 r1) = (reserve0, reserve1);
		require(out0 < r0 && out1 < r1, "liquidity");
		if (out0 > 0) token0.transfer(to, out0);
		if (out1 > 0) token1.transfer(to, out1);
		uint256 b0 = token0.balanceOf(address(this));
		uint256 b1 = token1.balanceOf(address(this));
		uint256 in0 = b0 > r0 - out0 ? b0 - (r0 - out0) : 0;
		uint256 in1 = b1 > r1 - out1 ? b1 - (r1 - out1) : 0;
		require(in0 > 0 || in1 > 0, "input");
		uint256 a0 = b0 * 1000 - in0 * 3;
		uint256 a1 = b1 * 1000 - in1 * 3;
		// The bug: the right side should be r0 * r1 * 1000**2.
		require(a0 * a1 >= r0 * r1 * 1000, "k");
		(reserve0, reserve1) = (b0, b1);
	}
}

/// Swaps along a path of pairs, each paying token0 for token1, the next pair's token0.
contract Router {
	function route(Pair[] calldata pairs, uint256 amountIn) external returns (uint256 amount) {
		amount = amountIn;
		for (uint256 i = 0; i < pairs.length; i++) {
			Pair pair = pairs[i];
			(uint256 r0, uint256 r1) = pair.getReserves();
			pair.token0().transfer(address(pair), amount);
			uint256 inWithFee = amount * 997;
			amount = inWithFee * r1 / (r0 * 1000 + inWithFee);
			pair.swap(0, amount, address(this));
		}
	}
}

/// Burns gas on keccak, arithmetic and memory: no state, so no proofs.
contract Burn {
	function burn(uint256 rounds) external pure returns (bytes32 h) {
		uint256[8] memory scratch;
		unchecked {
			for (uint256 i = 0; i < rounds; i++) {
				assembly {
					mstore(0, h)
					mstore(32, i)
					h := keccak256(0, 64)
				}
				scratch[i & 7] = uint256(h) * (i + 1) / ((i & 255) + 1);
			}
		}
		h ^= bytes32(scratch[3]);
	}
}

/// The pair bounty's invariant: pair 0's reserves' product never falls below what it was at the
/// bounty's block. The evm-report tool fixes both constants.
contract PairInvariant {
	Pair constant PAIR = Pair(0x000000000000000000000000000000000000A000);
	uint256 constant K0 = 1_000_000e18 * 1_000_000e18;

	fallback(bytes calldata) external returns (bytes memory) {
		(uint256 r0, uint256 r1) = PAIR.getReserves();
		return abi.encode(r0 * r1 >= K0);
	}
}
