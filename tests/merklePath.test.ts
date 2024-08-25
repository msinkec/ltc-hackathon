// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19

import * as dotenv from 'dotenv';
dotenv.config();

import { expect, use } from 'chai'
import { TestMerklePath } from '../src/contracts/tests/testMerklePath'
import chaiAsPromised from 'chai-as-promised'
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos } from './utils/txHelper';
import { Sha256, reverseByteString } from 'scrypt-ts';
import { prepProofFromElectrum, proofToBufferArray } from './utils/spv';
use(chaiAsPromised)


describe('Test SmartContract `TestMerklePath`', () => {
    let instance: TestMerklePath

    before(async () => {
        await TestMerklePath.loadArtifact()

        const merkleRoot = Sha256(
            reverseByteString(
                '07f6c431f7ac64189088d1506db9133cdefd576e6dad834b63de720d405d615d',
                32n
            )
        )

        instance = new TestMerklePath(merkleRoot)
    })

    it('merkle proof validation BTC', async () => {
        const seckey = new btc.PrivateKey(process.env.PRIVATE_KEY, btc.Networks.testnet)
        const pubkey = seckey.toPublicKey()
        const addrP2WPKH = seckey.toAddress(null, btc.Address.PayToWitnessPublicKeyHash)

        const xOnlyPub = pubkey.toBuffer().length > 32 ? pubkey.toBuffer().slice(1, 33) : pubkey.toBuffer()

        let scriptMerkle = new btc.Script(instance.lockingScript.toHex())
        const tapleafMerkle = Tap.encodeScript(scriptMerkle.toBuffer())
        const [tpubkeyMerkle, cblockMerkle] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafMerkle })
        const scripMerkleP2TR = new btc.Script(`OP_1 32 0x${tpubkeyMerkle}}`)

        // Fetch UTXO's for address
        const utxos = await fetchP2WPKHUtxos(addrP2WPKH)

        console.log(utxos)

        const tx0 = new btc.Transaction()
            .from(utxos)
            .addOutput(new btc.Transaction.Output({
                satoshis: 6000,
                script: scripMerkleP2TR
            }))
            .change(addrP2WPKH)
            .feePerByte(2)
            .sign(seckey)

        console.log('tx0 (serialized):', tx0.uncheckedSerialize())


        //////// CALL - UNLOCK

        const utxoMerkleP2TR = {
            txId: tx0.id,
            outputIndex: 0,
            script: scripMerkleP2TR,
            satoshis: 6000
        };

        const tx1 = new btc.Transaction()
            .from(utxoMerkleP2TR)
            .to(
                [
                    {
                        address: addrP2WPKH,
                        satoshis: 2000
                    }
                ]
            )

        const proofFromElectrum = {
            "block_height": 3385421,
            "merkle": [
                "b4539cc0a73acfbd36482a625130e02d17eb4eb462608e157c208b125992c921",
                "7fe250d466b2799e769276ae7f93d56b32e254a8148d4a321513f68668b15b03",
                "6bc372940a5bc7fbbb0a41d137480485875db7cdeb7b6128e5bf9c8aeefbbcfe"
            ],
            "pos": 2
        }
        
        const proofArr = proofToBufferArray(prepProofFromElectrum(proofFromElectrum))

        let witnesses = [
            Buffer.from('1326fca2320a618ce2e0916ced4e8ed13b052035da4dca51a5650c0f8970cd7c', 'hex').reverse(), // Leaf / TXID
            ...proofArr,
            scriptMerkle.toBuffer(),
            Buffer.from(cblockMerkle, 'hex')
        ]
        tx1.inputs[0].witnesses = witnesses
        console.log('tx1 (serialized):', tx1.uncheckedSerialize())


        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT
        let res = interpreter.verify(new btc.Script(''), tx0.outputs[0].script, tx1, 0, flags, witnesses, 6000)

        expect(res).to.be.true

    })

})
