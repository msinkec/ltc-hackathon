// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19

import * as dotenv from 'dotenv';
dotenv.config();

import { expect, use } from 'chai'
import { OrdListing } from '../src/contracts/ordinalListing'
import chaiAsPromised from 'chai-as-promised'
import { DISABLE_KEYSPEND_PUBKEY, fetchP2WPKHUtxos, getE, getSigHashSchnorr, splitSighashPreimage } from './utils/txHelper';
import { toByteString } from 'scrypt-ts';
import { prepProofFromElectrum, proofToBufferArray } from './utils/spv';
use(chaiAsPromised)


describe('Test SmartContract `OrdListing`', () => {

    before(async () => {
        await OrdListing.loadArtifact()
    })

    it('should pass', async () => {
        const seckey = new btc.PrivateKey(process.env.PRIVATE_KEY, btc.Networks.testnet)
        const pubkey = seckey.toPublicKey()
        const addrP2WPKH = seckey.toAddress(null, btc.Address.PayToWitnessPublicKeyHash)
        
        const listingPrice = 10000
        const ltcTxPaymentOutput = new btc.Transaction.Output({
                satoshis: listingPrice,
                script: new btc.Script(addrP2WPKH)
            })

        const instance = new OrdListing(
            toByteString(
                ltcTxPaymentOutput.toBufferWriter().toBuffer().toString('hex')
            )
        )
        const scriptOrdListing = instance.lockingScript
        const tapleafOrdListing = Tap.encodeScript(scriptOrdListing.toBuffer())
        
        const [tpubkeyCounter, cblockCounter] = Tap.getPubKey(DISABLE_KEYSPEND_PUBKEY, { target: tapleafOrdListing })
        const scriptCounterP2TR = new btc.Script(`OP_1 32 0x${tpubkeyCounter}}`)
        
        //////// Create fee outputs
        const feeAmtBuff = Buffer.alloc(8)
        feeAmtBuff.writeBigInt64LE(3500n)

        let utxos = await fetchP2WPKHUtxos(addrP2WPKH)
        if (utxos.length === 0){
            throw new Error(`No UTXO's for address: ${addrP2WPKH.toString()}`) 
        }
        console.log(utxos)

        const txFee = new btc.Transaction()
            .from(utxos)
            .to(addrP2WPKH, 3500)
            .to(addrP2WPKH, 3500)
            .change(addrP2WPKH)
            .feePerByte(2)
            .sign(seckey)

        console.log('txFee (serialized):', txFee.uncheckedSerialize())


        ///// CONTRACT DEPLOY
        
        const feeUTXODeploy = {
            address: addrP2WPKH.toString(),
            txId: txFee.id,
            outputIndex: 0,
            script: new btc.Script(addrP2WPKH),
            satoshis: txFee.outputs[0].satoshis
        }

        // TODO: First input should unlock from an UTXO holding an actual ordinal...
        const tx0 = new btc.Transaction()
            .from([feeUTXODeploy])
            .addOutput(new btc.Transaction.Output({
                satoshis: 546,
                script: scriptCounterP2TR
            }))
            .sign(seckey)

        console.log('tx0 (serialized):', tx0.uncheckedSerialize())

        //////// FIRST ITERATION

        const utxoCounterP2TR = {
            txId: tx0.id,
            outputIndex: 0,
            script: scriptCounterP2TR,
            satoshis: tx0.outputs[0].satoshis
        };

        const feeUTXO = {
            address: addrP2WPKH.toString(),
            txId: txFee.id,
            outputIndex: 1,
            script: new btc.Script(addrP2WPKH),
            satoshis: txFee.outputs[1].satoshis
        }

        const tx1 = new btc.Transaction()
            .from([utxoCounterP2TR, feeUTXO])
            .to(addrP2WPKH, 546)  // Ord destination after sale
            .to(addrP2WPKH, 1000) // TODO: Change

        // Mutate tx1 if it ends with 0x7f (highest single byte stack value) or 0xff (lowest signle byte stack value).
        let e, eBuff, sighash, eLastByte;
        while (true) {
            sighash = getSigHashSchnorr(tx1, Buffer.from(tapleafOrdListing, 'hex'), 0)
            e = await getE(sighash.hash)
            eBuff = e.toBuffer(32)
            eLastByte = eBuff[eBuff.length - 1]
            if (eLastByte != 0x7f && eLastByte != 0xff) {
                break;
            }
            tx1.nLockTime += 1
        }

        let _e = eBuff.slice(0, eBuff.length - 1) // e' - e without last byte
        let preimageParts = splitSighashPreimage(sighash.preimage)

        let sig = btc.crypto.Schnorr.sign(seckey, sighash.hash);

        // Also sign fee input
        let hashData = btc.crypto.Hash.sha256ripemd160(seckey.publicKey.toBuffer());
        let signatures = tx1.inputs[1].getSignatures(tx1, seckey, 1, undefined, hashData, undefined, undefined)
        tx1.inputs[1].addSignature(tx1, signatures[0])

        // TODO: Adjust to fit output we put in constructor...
        const ltcTx = new btc.Transaction('01000000000101a65b217509ce04223a1c8514f9166563164fed4758df05ba60f2bc66d8e77f470100000000ffffffff0280d1f00800000000160014f9cf09df52fb7becab667cdddc17d12a9d661def104be06603000000220020e61e53ae2fc2773585f4ef4da73ee6e1d794a4924b094aed16bf43108185519904004730440220053549fab8ffbe6a52d12bc9e862cccea423ea15011e9c1dcc22224c83102cb20220288fc59e1548f7fba82dd23698f9cbc354d672ed1c8d47b0d4b076bdd540053f014730440220226b261f85f66d0743612c5136d51918e08ae138649f92a4de78c610c454cb9802204da6830c6220bbb5029aba88c289c81b82939d4cb447ec2235f8f0db08462c900147522102ec4569774cda2671d75d996de9ebc3b88492f1684f56427d62c3fc06b410c64321023a198a8a6e687b61f9aa6a24c787930bc75a60c09b33c01fdebb1cd9d0e5594b52ae00000000')

        let ltcTxVer = Buffer.alloc(4)
        ltcTxVer.writeUInt32LE(ltcTx.version)

        let ltcTxLocktime = Buffer.alloc(4)
        ltcTxLocktime.writeUInt32LE(ltcTx.nLockTime)

        let ltcTxInputs = new btc.encoding.BufferWriter()
        ltcTxInputs.writeVarintNum(ltcTxInputs.inputs.length)
        ltcTx.inputs[0].toBufferWriter(ltcTxInputs);
        
        let ltcTxChangeOutput = new btc.encoding.BufferWriter()
        ltcTx.outputs[1].toBufferWriter(ltcTxChangeOutput);
        
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
            preimageParts.txVersion,
            preimageParts.nLockTime,
            preimageParts.hashPrevouts,
            preimageParts.hashSpentAmounts,
            preimageParts.hashScripts,
            preimageParts.hashSequences,
            preimageParts.hashOutputs,
            preimageParts.spendType,
            preimageParts.inputNumber,
            preimageParts.tapleafHash,
            preimageParts.keyVersion,
            preimageParts.codeseparatorPosition,
            sighash.hash,
            _e,
            Buffer.from(eLastByte.toString(16), 'hex'),

            ...proofArr,
            
            // TODO...

            Buffer.from('', 'hex'), // OP_0
            scriptOrdListing.toBuffer(),
            Buffer.from(cblockCounter, 'hex')
        ]
        tx1.inputs[0].witnesses = witnesses
        
        console.log('tx1 (serialized):', tx1.uncheckedSerialize())

        // Run locally
        let interpreter = new btc.Script.Interpreter()
        let flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT
        let res = interpreter.verify(new btc.Script(''), tx0.outputs[0].script, tx1, 0, flags, witnesses, tx0.outputs[0].satoshis)
        expect(res).to.be.true
    })
})