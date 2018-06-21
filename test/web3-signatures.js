// Copyright (c) 2016-2018 Clearmatics Technologies Ltd
// SPDX-License-Identifier: LGPL-3.0+

const ethUtil = require('ethereumjs-util');

const Web3 = require('web3');
const Web3Utils = require('web3-utils');
const Web3Abi = require('web3-eth-abi');
const Web3Accounts = require('web3-eth-accounts');

const web3 = new Web3();

web3.setProvider(new web3.providers.HttpProvider('http://localhost:8545'));

function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

contract.only('web3-signatures.js', (accounts) => {
  const joinHex = arr => '0x' + arr.map(el => el.slice(2)).join('')

  it('Test: web3.eth.sign', async () => {
    const msg = new Buffer('hello');
    const sig = web3.eth.sign(web3.eth.accounts[0], '0x' + msg.toString('hex'));
    const res = ethUtil.fromRpcSig(sig);

    const prefix = new Buffer("\x19Ethereum Signed Message:\n");
    const prefixedMsg = ethUtil.sha3(
      Buffer.concat([prefix, new Buffer(String(msg.length)), msg])
    );

    const pubKey  = ethUtil.ecrecover(prefixedMsg, res.v, res.r, res.s);
    const addrBuf = ethUtil.pubToAddress(pubKey);
    const addr    = ethUtil.bufferToHex(addrBuf);

    console.log(web3.eth.accounts[0],  addr);
  })

  it('Test: ethereumjs-util.ecsign', async () => {
    const privateKey = Buffer.from('4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d', 'hex')
    const msg = new Buffer('hello');

    const msgHash = ethUtil.sha3(msg);

    const sig = ethUtil.ecsign(msgHash, privateKey)
    if (this._chainId > 0) {
      sig.v += this._chainId * 2 + 8
    }

    const pubKey  = ethUtil.ecrecover(msgHash, sig.v, sig.r, sig.s);
    const addrBuf = ethUtil.pubToAddress(pubKey);
    const addr    = ethUtil.bufferToHex(addrBuf);

    console.log(web3.eth.accounts[0],  addr);
  })

});
