// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

struct PublicValuesStruct {
    bool is_valid;
}

/// @title zkDNSSEC.
/// @author Vedant Chainani
/// @notice This contract integrates zero-knowledge proofs into DNSSEC verification, enabling validation of DNS records (TXT, RRSIG, DNSKEY) without revealing their contents
contract ZKDNSSEC {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifier;

    /// @notice The verification key for the zkDNSSEC program.
    bytes32 public fibonacciProgramVKey;

    constructor(address _verifier, bytes32 _fibonacciProgramVKey) {
        verifier = _verifier;
        fibonacciProgramVKey = _fibonacciProgramVKey;
    }

    /// @notice The entrypoint for verifying the proof of a record.
    /// @param _proofBytes The encoded proof.
    /// @param _publicValues The encoded public values.
    function verifyDNSSECRecord(bytes calldata _publicValues, bytes calldata _proofBytes) public view returns (bool) {
        ISP1Verifier(verifier).verifyProof(fibonacciProgramVKey, _publicValues, _proofBytes);
        PublicValuesStruct memory publicValues = abi.decode(_publicValues, (PublicValuesStruct));
        return (publicValues.is_valid);
    }
}
