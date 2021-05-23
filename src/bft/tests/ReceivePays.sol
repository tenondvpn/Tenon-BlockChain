// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract ReceiverPays {
    address owner = msg.sender;

    mapping(uint256 => bool) usedNonces;
    mapping(uint256 => bytes) usedNonces2;
    mapping(uint256 => address) usedNonces3;
    mapping(uint256 => uint256) usedNonces4;
    mapping(uint256 => bytes32) usedNonces5;
    mapping(uint256 => uint8) usedNonces6;

    constructor() payable {
    }

    // 收款方认领付款
    function claimPayment(uint256 amount, uint256 nonce, bytes memory signature) public {
        //require(!usedNonces[nonce]);
        //usedNonces[nonce] = true;

        // 重建在客户端签名的信息
        //bytes32 message = prefixed(keccak256(abi.encode(msg.sender, amount, nonce, this)));
        //usedNonces5[nonce] = message; 
        //(uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        //usedNonces6[nonce] = v;
        //usedNonces5[nonce] = r;
        //usedNonces5[nonce] = s;
        uint8 v1 = 0x1b;
        bytes32 r1 = 0x3d584400dc77e383a2a2860d15fd181b1c36117d7b6c1e5d54e2f21d9491b66e;
        bytes32 s1 = 0x043a539fab3f2e42ba806da59b30e100077a7dba7439de3fce427eaa75dce5c4;
        bytes32 message2 = 0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d5;
        //require(v == v1);
        //require(r == r1);
        //require(s == s1);
        //require(message == message2);
/*
    bool ret;
    address addr;

    assembly {
        let size := mload(0x40)
        mstore(size, message2)
        mstore(add(size, 32), v1)
        mstore(add(size, 64), r1)
        mstore(add(size, 96), s1)
        ret := call(3000, 1, 0, size, 128, size, 32)
        addr := mload(size)
    }
require(addr == owner);
  */      
        address rec_addr = ecrecover(message2, v1, r1, s1);
        require(rec_addr == owner);
        //require(recoverSigner(message2, signature) == owner);

        payable(msg.sender).transfer(amount);
    }


function stringToBytes32(string memory source) public pure returns (bytes32 result) {
    bytes memory tempEmptyStringTest = bytes(source);
    if (tempEmptyStringTest.length == 0) {
        return 0x0;
    }

    assembly {
        result := mload(add(source, 32))
    }
}
    /// destroy the contract and reclaim the leftover funds.
    function kill() public {
        require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }

    /// 第三方方法，分离签名信息的 v r s
    function splitSignature(bytes memory sig)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(sig.length == 65);

        assembly {
            // first 32 bytes, after the length prefix.
            r := mload(add(sig, 32))
            // second 32 bytes.
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes).
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }

    function recoverSigner(bytes32 message, bytes memory sig)
        internal
        pure
        returns (address)
    {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(message, v, r, s);
    }

    /// 加入一个前缀，因为在eth_sign签名的时候会加上。
    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
