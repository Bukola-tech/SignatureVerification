// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SignatureVerification {
    IERC20 public token;
    mapping(address => bool) public whitelist;
    mapping(address => bool) public claimed;

    constructor(address _tokenAddress, address[] memory _whitelist) {
        token = IERC20(_tokenAddress);
        for (uint i = 0; i < _whitelist.length; i++) {
            whitelist[_whitelist[i]] = true;
        }
    }

    function claimTokens(uint256 amount, bytes32 messageHash, bytes memory signature) external {
        require(whitelist[msg.sender], "Not whitelisted");
        require(!claimed[msg.sender], "Already claimed");

        // Verify signature
        bytes32 prefixedHash = getEthSignedMessageHash(messageHash);
        address signer = recoverSigner(prefixedHash, signature);
        require(signer == msg.sender, "Invalid signature");

        claimed[msg.sender] = true;
        require(token.transfer(msg.sender, amount), "Token transfer failed");
    }

    // Hash the message to match the Ethereum signed message format
    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    // Recover the signer address from the signature
    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    // Split the signature into r, s, and v components
    function splitSignature(bytes memory _sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_sig.length == 65, "Invalid signature length");
        assembly {
            // First 32 bytes stores the length of the signature
            // Skip the first 32 bytes, and get the r value
            r := mload(add(_sig, 32))
            // Next 32 bytes is s
            s := mload(add(_sig, 64))
            // Final byte (first byte of the next 32 bytes) is v
            v := byte(0, mload(add(_sig, 96)))
        }
    }
}
