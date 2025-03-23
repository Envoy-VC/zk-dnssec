// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZKDNSSEC} from "../../src/ZKDNSSEC.sol";
import {SP1VerifierGateway, ISP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

struct SP1ProofFixtureJson {
    bool isValid;
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract ZKDNSSECGroth16ForkTest is Test {
    using stdJson for string;

    uint256 mainnetFork;
    address verifier = address(0x397A5f7f3dBd538f23DE225B51f532c34448dA9B);

    ZKDNSSEC public dnssec;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/groth16-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        mainnetFork = vm.createFork(vm.envString("ETH_RPC_URL_MAINNET"));
        vm.selectFork(mainnetFork);
        SP1ProofFixtureJson memory fixture = loadFixture();
        dnssec = new ZKDNSSEC(verifier, fixture.vkey);
    }

    function test_ValidDNSSECProof() public {
        vm.skip(true);
        vm.selectFork(mainnetFork);
        SP1ProofFixtureJson memory fixture = loadFixture();

        bool isValid = dnssec.verifyDNSSECRecord(fixture.publicValues, fixture.proof);
        console.log("isValid: ", isValid);
        assert(isValid == fixture.isValid);
    }

    function testFail_InvalidDNSSECProof() public {
        vm.skip(true);
        vm.selectFork(mainnetFork);
        SP1ProofFixtureJson memory fixture = loadFixture();

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);

        dnssec.verifyDNSSECRecord(fixture.publicValues, fakeProof);
    }
}

contract DNSSECPlonkForkTest is Test {
    using stdJson for string;

    address verifier = address(0x3B6041173B80E77f038f3F2C0f9744f04837185e);
    uint256 mainnetFork;
    ZKDNSSEC public dnssec;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/plonk-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        mainnetFork = vm.createFork(vm.envString("ETH_RPC_URL_MAINNET"));
        vm.selectFork(mainnetFork);
        SP1ProofFixtureJson memory fixture = loadFixture();
        dnssec = new ZKDNSSEC(verifier, fixture.vkey);
    }

    function test_ValidDNSSECRecordProof() public {
        vm.skip(true);
        vm.selectFork(mainnetFork);
        SP1ProofFixtureJson memory fixture = loadFixture();

        bool isValid = dnssec.verifyDNSSECRecord(fixture.publicValues, fixture.proof);
        assert(isValid == fixture.isValid);
    }

    function testFail_InvalidZKDNSSECProof() public {
        vm.skip(true);
        vm.selectFork(mainnetFork);
        SP1ProofFixtureJson memory fixture = loadFixture();

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);
        dnssec.verifyDNSSECRecord(fixture.publicValues, fakeProof);
    }
}
