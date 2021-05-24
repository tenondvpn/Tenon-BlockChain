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
var param_codes = web3.eth.abi.encodeParameters(['address', 'uint256'], ['0x6dc5556448eef3f33ae013d03e50da1c2b8c4901', '10000000']);
console.log("param_codes: " + param_codes);
var kek256 = web3.utils.keccak256(param_codes);
console.log("kek256: " + kek256);
var param_code_hash = web3.eth.accounts.hashMessage(kek256)
console.log("param_code_hash: " + param_code_hash)
var sig_param = web3.eth.accounts.sign(kek256, '0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709');
console.log("sig params: ");
console.log(sig_param);
var recover = web3.eth.accounts.recover({
    messageHash: param_code_hash,
    v: sig_param.v,
    r: sig_param.r,
    s: sig_param.s
});
console.log('recover: ' + recover);


// func code
var closeFunc = web3.eth.abi.encodeFunctionSignature('close(uint256,bytes)');
console.log("closeFunc function code: " + closeFunc);

var extendFunc = web3.eth.abi.encodeFunctionSignature('extend(uint256)');
console.log("extendFunc function code: " + extendFunc);

var claimTimeoutFunc = web3.eth.abi.encodeFunctionSignature('claimTimeout()');
console.log("claimTimeoutFunc function code: " + claimTimeoutFunc);

// params code
var constructerCode = web3.eth.abi.encodeParameters(['address', 'uint256'], ['0xdc09e1166271813aac21ff255960dcf39ccc000b', '100']);
console.log("constructerCode: " + constructerCode);

var closeCode = web3.eth.abi.encodeParameters(['uint256', 'bytes'], ['10000000', sig_param.signature]);
console.log("closeCode: " + closeCode);

var extendCode = web3.eth.abi.encodeParameters(['uint256'], ['100']);
console.log("extendCode: " + extendCode);


