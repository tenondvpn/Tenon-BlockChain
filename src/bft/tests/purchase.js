const Web3 = require('web3')
var web3;

if (typeof web3 !== 'undefined') {
    web3 = new Web3(web3.currentProvider);
} else {
    web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
}
/*
var address = "0xd77caeda977ae75924879da5057de4dfaafb63fb"
web3.eth.getBalance(address, (err, wei) => {

    // 余额单位从wei转换为ether
    balance = web3.utils.fromWei(wei, 'ether')
    console.log("balance: " + balance)
})
*/
var account = web3.eth.getAccounts()[0];
var accs = web3.eth.getAccounts();
var sha3Msg = web3.utils.sha3("blockchain");
//var signedData = web3.eth.sign(account, sha3Msg);
console.log("account 0: " + account)
console.log(sha3Msg)
console.log(accs)


//web3.eth.getAccounts(console.log);



var web3 = new Web3('http://localhost:8545');
// or
var web3 = new Web3(new Web3.providers.HttpProvider('http://localhost:8545'));

// change provider
web3.setProvider('ws://localhost:8546');
// or
web3.setProvider(new Web3.providers.WebsocketProvider('ws://localhost:8546'));

// Using the IPC provider in node.js
var net = require('net');
var web3 = new Web3('/Users/myuser/Library/Ethereum/geth.ipc', net); // mac os path
// or
var web3 = new Web3(new Web3.providers.IpcProvider('/Users/myuser/Library/Ethereum/geth.ipc', net)); // mac os path
// on windows the path is: "\\\\.\\pipe\\geth.ipc"
// on linux the path is: "/users/myuser/.ethereum/geth.ipc"

var hash = web3.eth.accounts.hashMessage("Some data")
console.log(hash)

var sign = web3.eth.accounts.sign('Some data', '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318');
console.log(sign)

var recover = web3.eth.accounts.recover({
    messageHash: '0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655',
    v: '0x1c',
    r: '0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd',
    s: '0x6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a029'
})
console.log(recover)


web3.eth.abi;
var res_sha3 = web3.utils.soliditySha3('a', 'b', 'c', 'd')
console.log("res_sha3: " + res_sha3)












console.log("test smart contract signature: ");
var account1 = web3.eth.accounts.privateKeyToAccount('0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709'); 
console.log("from :");
console.log(account1);
var account2 = web3.eth.accounts.privateKeyToAccount('0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700');
console.log("to :");
console.log(account2);

var contract_addr = web3.eth.accounts.privateKeyToAccount('0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8704');
console.log("contract_addr:");
console.log(contract_addr);

var param_codes = web3.eth.abi.encodeParameters(['address', 'uint256', 'uint256', 'address'], ['0xaf5E8eABEd304DfeF8c8effBd7490d6FAfe9bAE3', '2643000000', '1', '0x2f6acD655C36FF98398ee8729D3c92f35A1f147E']);
console.log("param_codes: " + param_codes);


var kek256 = web3.utils.keccak256(param_codes);
console.log("kek256: " + kek256);

var param_code_hash = web3.eth.accounts.hashMessage(kek256)
console.log("param_code_hash: " + param_code_hash)

var kek256_test = web3.utils.keccak256(web3.eth.abi.encodeParameters(['string',],["Some data",]));
console.log("kek256 test: " + kek256_test);

var sig_param = web3.eth.accounts.sign(kek256, '0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709');
console.log("sig params: ");
console.log(sig_param);

var recover = web3.eth.accounts.recover({messageHash: '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d5', v: '0x1b', r: '0x3d584400dc77e383a2a2860d15fd181b1c36117d7b6c1e5d54e2f21d9491b66e', s: '0x043a539fab3f2e42ba806da59b30e100077a7dba7439de3fce427eaa75dce5c4'});
console.log('recover: ' + recover);


var bidCode = web3.eth.abi.encodeFunctionSignature('bid(bytes32)');
console.log("bidCode function code: " + bidCode);

var revealCode = web3.eth.abi.encodeFunctionSignature('reveal(uint256[],bool[],bytes32[])');
console.log("revealCode function code: " + revealCode);

var withdrawCode = web3.eth.abi.encodeFunctionSignature('withdraw()');
console.log("withdrawCode function code: " + withdrawCode);

var auctionEndCode = web3.eth.abi.encodeFunctionSignature('auctionEnd()');
console.log("auctionEndCode function code: " + auctionEndCode);

// params
var contriuctParam = web3.eth.abi.encodeParameters(['uint256', 'uint256', 'address'], ['1000', '2000', '0xd31f18f44c3b6c3d4f9e23ea7317805488cee731']);
console.log("contriuctParam: " + contriuctParam);

var blindedBid1_1 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['4000', false, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d1']));
var bidParma1_1 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid1_1]);
var blindedBid1_2 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['3000', true, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d2']));
var bidParma1_2 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid1_2]);
var blindedBid1_3 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['2000', false, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d3']));
var bidParma1_3 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid1_3]);
var blindedBid1_4 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['6000', false, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d4']));
var bidParma1_4 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid1_4]);
var blindedBid1_5 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['7000', true, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d5']));
var bidParma1_5 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid1_5]);
console.log("bidParma1_1: " + bidParma1_1);
console.log("bidParma1_2: " + bidParma1_2);
console.log("bidParma1_3: " + bidParma1_3);
console.log("bidParma1_4: " + bidParma1_4);
console.log("bidParma1_5: " + bidParma1_5);

var revealParam1 = web3.eth.abi.encodeParameters(['uint256[]', 'bool[]', 'bytes32[]'], [
    ['4000', '3000', '2000', '6000', '7000'],
    [false, true, false, false, true],
    ['0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d1',
        '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d2',
        '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d3',
        '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d4',
        '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d5',]
]);
console.log("revealParam1: " + revealParam1);

var blindedBid2_1 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['5000', false, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c1']));
var bidParma2_1 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid2_1]);
var blindedBid2_2 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['6000', true, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c2']));
var bidParma2_2 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid2_2]);
var blindedBid2_3 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['7000', false, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c3']));
var bidParma2_3 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid2_3]);
var blindedBid2_4 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['6000', false, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c4']));
var bidParma2_4 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid2_4]);
var blindedBid2_5 = web3.utils.keccak256(web3.eth.abi.encodeParameters(['uint256', 'bool', 'bytes32'], ['4000', true, '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c5']));
var bidParma2_5 = web3.eth.abi.encodeParameters(['bytes32'], [blindedBid2_5]);
console.log("bidParma2_1: " + bidParma2_1);
console.log("bidParma2_2: " + bidParma2_2);
console.log("bidParma2_3: " + bidParma2_3);
console.log("bidParma2_4: " + bidParma2_4);
console.log("bidParma2_5: " + bidParma2_5);

var revealParam2 = web3.eth.abi.encodeParameters(['uint256[]', 'bool[]', 'bytes32[]'], [
    ['5000', '6000', '7000', '6000', '4000'],
    [false, true, false, false, true],
    ['0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c1',
        '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c2',
        '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c3',
        '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c4',
        '0xf559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93c5',]
]);

console.log("revealParam2: " + revealParam2);




