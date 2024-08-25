import {
    assert,
    ByteString,
    hash256,
    len,
    method,
    prop,
    Sha256,
    sha256,
    SmartContract,
    toByteString,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'
import { MerklePath, MerkleProof } from './merklePath'


export class OrdListing extends SmartContract {

    @prop()
    ltcTxPaymentOutput: ByteString

    /**
     *
     * @param ltcTxPaymentOutput  - Serialized output from LTC transaction that pays seller.
     */
    constructor(ltcTxPaymentOutput: ByteString) {
        super(...arguments)
        this.ltcTxPaymentOutput = ltcTxPaymentOutput
    }

    @method()
    public unlock(
        shPreimage: SHPreimage,
        ltcPaymentProof: MerkleProof,

        ltcTxVer: ByteString,
        ltcTxLocktime: ByteString,
        ltcTxInputs: ByteString,  // Length prefixed
        ltcTxChangeOutput: ByteString,

        ordDestOutput: ByteString,
        changeOutput: ByteString
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))
        

        // Construct LTC transactions ID.
        assert(len(ltcTxVer) == 4n)
        assert(len(ltcTxLocktime) == 4n)
        const ltcTxId = hash256(
            ltcTxVer +
            ltcTxInputs +
            toByteString('02') +
            this.ltcTxPaymentOutput +
            ltcTxChangeOutput +
            ltcTxLocktime
        )
        
        // Check LTC payment proof.
        this.checkProof(ltcPaymentProof, ltcTxId)

        // Construct outputs and compare against hash in sighash preimage.
        const hashOutputs = sha256(
            ordDestOutput + changeOutput
        )
        assert(hashOutputs == shPreimage.hashOutputs, 'hashOutputs mismatch')
    }
    
    @method()
    private checkProof(
        ltcPaymentProof: MerkleProof,
        ltcTxId: Sha256
    ): void {
        const merkleRoot =  MerklePath.calcMerkleRoot(ltcTxId, ltcPaymentProof)
        
        // TODO: Check oracle sig.
        assert(true)
    }

}