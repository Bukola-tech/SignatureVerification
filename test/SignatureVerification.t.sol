// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/SignatureVerification.sol";
import "../src/BuksToken.sol";;

contract SignatureVerificationTest is Test {
    SignatureVerification public signatureContract;
    ERC20 public token;
    address public alice;
    address[] public whitelist;

    function setUp() public {
        // Deploy ERC20 token and mint some tokens
        token = new ERC20("Test Token", "TKN");
        token._mint(address(this), 1000 * 10**18);

        // Whitelist addresses
        alice = address(0x123);
        whitelist.push(alice);

        // Deploy the SignatureVerification contract
        signatureContract = new SignatureVerification(address(token), whitelist);

        // Send some tokens to the contract for distribution
        token.transfer(address(signatureContract), 500 * 10**18);
    }

    function testClaimTokensWithValidSignature() public {
        // Create a valid signature for Alice
        uint256 amount = 100 * 10**18;
        bytes32 messageHash = keccak256(abi.encodePacked(amount, alice));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, messageHash); // Signing with alice's private key
        
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(alice); // Pretend to be Alice
        signatureContract.claimTokens(amount, messageHash, signature);

        // Check if Alice received the tokens
        assertEq(token.balanceOf(alice), amount);
        assertTrue(signatureContract.claimed(alice));
    }

    function testFailClaimWithInvalidSignature() public {
        // Using Bob's private key to sign the message, but trying to claim as Alice
        address bob = address(0x456);
        uint256 amount = 100 * 10**18;
        bytes32 messageHash = keccak256(abi.encodePacked(amount, alice));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, messageHash); // Signing with Bob's private key
        
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(alice); // Pretend to be Alice
        signatureContract.claimTokens(amount, messageHash, signature);
    }
}
