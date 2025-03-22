// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZKDNSSEC} from "../src/ZKDNSSEC.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

struct SP1ProofFixtureJson {
    bool is_valid;
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract ZKDNSSECGroth16Test is Test {
    using stdJson for string;

    address verifier;
    ZKDNSSEC public dnssec;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/groth16-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        dnssec = new ZKDNSSEC(verifier, fixture.vkey);
    }

    function test_ValidDNSSECProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        (bool is_valid) = dnssec.verifyDNSSECRecord(fixture.publicValues, fixture.proof);
        assert(is_valid == fixture.is_valid);
    }

    function testFail_InvalidDNSSECProof() public view {
        SP1ProofFixtureJson memory fixture = loadFixture();

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);

        dnssec.verifyDNSSECRecord(fixture.publicValues, fakeProof);
    }
}

contract DNSSECPlonkTest is Test {
    using stdJson for string;

    address verifier;
    ZKDNSSEC public dnssec;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/plonk-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        dnssec = new ZKDNSSEC(verifier, fixture.vkey);
    }

    function test_ValidDNSSECRecordProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        (bool is_valid) = dnssec.verifyDNSSECRecord(fixture.publicValues, fixture.proof);
        assert(is_valid == fixture.is_valid);
    }

    function testFail_InvalidFibonacciProof() public view {
        SP1ProofFixtureJson memory fixture = loadFixture();

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);

        dnssec.verifyDNSSECRecord(fixture.publicValues, fakeProof);
    }
}
