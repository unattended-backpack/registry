// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { ICreateX } from "../src/interfaces/ICreateX.sol";
import { EmailProof } from "../src/interfaces/IVerifier.sol";
import { Registry } from "../src/Registry.sol";
import { Groth16Verifier } from "../src/vendor/Groth16Verifier.sol";
import { Verifier } from "../src/Verifier.sol";
import { MockVerifier } from "./mocks/MockVerifier.sol";
import { Test } from "forge-std/Test.sol";
import { LibString } from "solady/utils/LibString.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RegistryForkTest
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A mainnet fork test suite validating CREATE3 deployment of the Registry and
  of the immutable verifier pair through the real CreateX factory, and that
  the deployed bytecode runs an email registration end to end. ZK Email
  publishes no mainnet verifier, so the registry tests run against a mock
  verifier deployed onto the fork; the policy around it is the unit suite's
  business.

  Every test skips unless `MAINNET_RPC_URL` is set (an ordinary mainnet RPC
  suffices to fork the latest block; pinning `MAINNET_FORK_BLOCK` to an older
  block requires an archive node).

  @custom:date August 21st, 2026.
*/
contract RegistryForkTest is
  Test {

  using LibString for address;

  using LibString for uint256;

  /// The CreateX factory on Ethereum mainnet.
  address internal constant CREATEX =
    0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

  /// An arbitrary unguarded salt for exercising CREATE3 deployment.
  bytes32 internal constant FORK_SALT = keccak256("registry.fork.test");

  /// A DKIM key hash management honors for the domain.
  bytes32 internal constant KEY_HASH = keccak256("ethereum.org dkim key");

  /// The mainnet RPC URL fork tests run against; empty skips the suite.
  string internal forkUrl;

  /// The mock proof verifier, deployed onto the fork.
  MockVerifier internal verifier;

  /// The management multisig.
  address internal management = makeAddr("management");

  /// A wallet Alice binds as her controller.
  address internal aliceWallet = makeAddr("aliceWallet");

  /// Skip the test unless a mainnet fork RPC is configured.
  modifier onlyForked () {
    vm.skip(bytes(forkUrl).length == 0);
    _;
  }

  /// Fork mainnet and deploy the mock verifier onto it.
  function setUp () public {
    forkUrl = vm.envOr("MAINNET_RPC_URL", string(""));
    if (bytes(forkUrl).length == 0) {
      return;
    }
    string memory _forkBlock = vm.envOr("MAINNET_FORK_BLOCK", string(""));
    if (bytes(_forkBlock).length == 0) {
      vm.createSelectFork(forkUrl);
    } else {
      vm.createSelectFork(forkUrl, vm.parseUint(_forkBlock));
    }
    verifier = new MockVerifier();

    /*
      Deterministic test addresses exist on the real chain and may carry real
      state (code, balances). Strip code so every actor behaves like a clean
      account.
    */
    vm.etch(management, hex"");
    vm.etch(aliceWallet, hex"");
  }

  /**
    Deploy the Registry through the real CreateX factory.

    @return _ The deployed registry.
  */
  function _deploy () internal returns (Registry) {
    address _deployed =
      ICreateX(CREATEX).deployCreate3(
        FORK_SALT,
        abi.encodePacked(
          type(Registry).creationCode,
          abi.encode(address(verifier), "ethereum.org", management)
        )
      );

    // Management honors the domain's current DKIM key hash.
    vm.prank(management);
    Registry(_deployed).setDKIMPublicKeyHash(KEY_HASH, true);
    return Registry(_deployed);
  }

  /// The registry deploys through the real CreateX factory and wires itself up.
  function test_fork_createXDeployment () public onlyForked {
    Registry _registry = _deploy();
    assertGt(address(_registry).code.length, 0);
    assertEq(address(_registry.verifier()), address(verifier));
    assertTrue(_registry.dkimPublicKeyHashes(KEY_HASH));
    assertEq(_registry.domain(), "ethereum.org");
    assertEq(_registry.management(), management);
    assertEq(_registry.profileCount(), 0);
  }

  /// The CreateX-deployed bytecode registers a profile by email end to end.
  function test_fork_emailRegistration () public onlyForked {
    Registry _registry = _deploy();
    bytes32 _alice = keccak256("alice@ethereum.org|code");
    string memory _command =
      string.concat(
        "Set controller to ", aliceWallet.toHexStringChecksummed(), " ",
        block.chainid.toString(), ":",
        address(_registry).toHexStringChecksummed()
      );
    EmailProof memory _p = EmailProof({
      domainName: "ethereum.org",
      publicKeyHash: KEY_HASH,
      timestamp: block.timestamp,
      maskedCommand: _command,
      emailNullifier: keccak256("fork email"),
      accountSalt: _alice,
      isCodeExist: true,
      proof: "valid"
    });
    _registry.register(_p, aliceWallet);
    (address _controller, bool _active, , ) = _registry.profiles(_alice);
    assertEq(_controller, aliceWallet);
    assertTrue(_active);
    vm.prank(aliceWallet);
    _registry.setText(_alice, "url", "https://alice.example");
    assertEq(_registry.text(_alice, "url"), "https://alice.example");
    vm.prank(management);
    _registry.setActive(_alice, false);
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InactiveProfile.selector, _alice)
    );
    _registry.setText(_alice, "url", "https://elsewhere.example");
  }

  /**
    The immutable verifier pair deploys through the real CreateX factory, and
    its real pairing check rejects a proof that is not a proof.
  */
  function test_fork_verifierDeployment () public onlyForked {
    address _groth16 =
      ICreateX(CREATEX).deployCreate3(
        keccak256("registry.fork.groth16"), type(Groth16Verifier).creationCode
      );
    address _immutableVerifier =
      ICreateX(CREATEX).deployCreate3(
        keccak256("registry.fork.verifier"),
        abi.encodePacked(type(Verifier).creationCode, abi.encode(_groth16))
      );
    Verifier _v = Verifier(_immutableVerifier);
    assertEq(address(_v.groth16Verifier()), _groth16);
    assertEq(_v.commandBytes(), 605);
    Registry _registry =
      Registry(
        ICreateX(CREATEX).deployCreate3(
          keccak256("registry.fork.real"),
          abi.encodePacked(
            type(Registry).creationCode,
            abi.encode(_immutableVerifier, "ethereum.org", management)
          )
        )
      );
    vm.prank(management);
    _registry.setDKIMPublicKeyHash(KEY_HASH, true);
    uint256[2] memory _pA = [uint256(1), uint256(2)];
    uint256[2][2] memory _pB =
      [[uint256(1), uint256(2)], [uint256(3), uint256(4)]];
    uint256[2] memory _pC = [uint256(1), uint256(2)];
    EmailProof memory _p = EmailProof({
      domainName: "ethereum.org",
      publicKeyHash: KEY_HASH,
      timestamp: block.timestamp,
      maskedCommand: _registry.setControllerCommand(aliceWallet),
      emailNullifier: keccak256("fork verifier email"),
      accountSalt: keccak256("alice@ethereum.org|code"),
      isCodeExist: true,
      proof: abi.encode(_pA, _pB, _pC)
    });
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    _registry.register(_p, aliceWallet);
  }
}

