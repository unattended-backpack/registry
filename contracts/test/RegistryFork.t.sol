// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { ICreateX } from "../src/interfaces/ICreateX.sol";
import { EmailProof } from "../src/interfaces/IVerifier.sol";
import { Registry } from "../src/Registry.sol";
import { HonkVerifier } from "../src/vendor/HonkVerifier.sol";
import { Verifier } from "../src/Verifier.sol";
import { MockVerifier } from "./mocks/MockVerifier.sol";
import { Test } from "forge-std/Test.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RegistryForkTest
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A fork test suite rehearsing deployment on the chain `RPC_URL` names, the
  same chain the deployment goals target: CREATE3 deployment of the Registry
  and of the immutable verifier pair through the real CreateX factory, and an
  email registration end to end on the deployed bytecode. A real email
  binds one chain and one registry address, so the registration test runs
  against a mock verifier deployed onto the fork; the real verifier pair is
  checked against a real proof directly.

  Every test skips unless `RPC_URL` is set (an ordinary RPC suffices to fork
  the latest block; pinning `FORK_BLOCK` to an older block requires an archive
  node).

  @custom:date October 5th, 2026.
*/
contract RegistryForkTest is
  Test {

  /// The CreateX factory, at the same address on every chain it serves.
  address internal constant CREATEX =
    0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

  /// An arbitrary unguarded salt for exercising CREATE3 deployment.
  bytes32 internal constant FORK_SALT = keccak256("registry.fork.test");

  /// A DKIM key hash management honors for the domain.
  bytes32 internal constant KEY_HASH = keccak256("ethereum.org dkim key");

  /// The registry address the proof vectors bind, on anvil's chain.
  address internal constant BOUND_REGISTRY =
    0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

  /// The RPC URL of the chain fork tests run against; empty skips the suite.
  string internal forkUrl;

  /// The mock proof verifier, deployed onto the fork.
  MockVerifier internal verifier;

  /// The management multisig.
  address internal management = makeAddr("management");

  /// A wallet Alice binds as her controller.
  address internal aliceWallet = makeAddr("aliceWallet");

  /// Skip the test unless a fork RPC is configured.
  modifier onlyForked () {
    vm.skip(bytes(forkUrl).length == 0);
    _;
  }

  /// Fork the deployment chain and deploy the mock verifier onto it.
  function setUp () public {
    forkUrl = vm.envOr("RPC_URL", string(""));
    if (bytes(forkUrl).length == 0) {
      return;
    }
    string memory _forkBlock = vm.envOr("FORK_BLOCK", string(""));
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
    bytes32 _alice = keccak256("alice's private profile");
    EmailProof memory _p = EmailProof({
      domainName: "ethereum.org",
      publicKeyHash: KEY_HASH,
      timestamp: block.timestamp,
      emailNullifier: keccak256("fork email"),
      profileId: _alice,
      proof: abi.encode(
        keccak256("valid"), aliceWallet, block.chainid, address(_registry)
      )
    });
    _registry.register(_p, aliceWallet);
    (address _controller, bool _active, , ) = _registry.profiles(_alice);
    assertEq(_controller, aliceWallet);
    assertTrue(_active);
    assertTrue(_registry.isActive(_alice));
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
    The immutable verifier pair deploys through the real CreateX factory,
    accepts a real proof for the registry and chain it binds, and, behind a
    registry it does not bind, refuses it.
  */
  function test_fork_verifierDeployment () public onlyForked {
    address _honk =
      ICreateX(CREATEX).deployCreate3(
        keccak256("registry.fork.honk"), type(HonkVerifier).creationCode
      );
    address _immutableVerifier =
      ICreateX(CREATEX).deployCreate3(
        keccak256("registry.fork.verifier"),
        abi.encodePacked(type(Verifier).creationCode, abi.encode(_honk))
      );
    Verifier _v = Verifier(_immutableVerifier);
    assertEq(address(_v.honkVerifier()), _honk);
    string memory _json =
      vm.readFile("../circuits/test/vectors/synthetic-register.proof.json");
    EmailProof memory _real = EmailProof({
      domainName: vm.parseJsonString(_json, ".domainName"),
      publicKeyHash: vm.parseJsonBytes32(_json, ".publicKeyHash"),
      timestamp: vm.parseJsonUint(_json, ".timestamp"),
      emailNullifier: vm.parseJsonBytes32(_json, ".emailNullifier"),
      profileId: vm.parseJsonBytes32(_json, ".profileId"),
      proof: vm.parseJsonBytes(_json, ".proof")
    });
    address _controller = vm.parseJsonAddress(_json, ".controller");

    /*
      The proof binds anvil's chain and its demo registry; as that registry, on
      that chain, it verifies.
    */
    uint256 _forked = block.chainid;
    vm.chainId(31337);
    vm.prank(BOUND_REGISTRY);
    assertTrue(
      _v.verifyEmailProof(_real, _controller), "a real proof verifies"
    );
    vm.chainId(_forked);

    // A registry on the forked chain refuses it: it binds another deployment.
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
    _registry.setDKIMPublicKeyHash(_real.publicKeyHash, true);
    vm.warp(_real.timestamp + 1 days);
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    _registry.register(_real, _controller);
  }
}

