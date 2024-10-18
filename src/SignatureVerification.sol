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

    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory _sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
    }
}
