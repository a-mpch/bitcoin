#!/usr/bin/env python3
# Copyright (c) 2024-2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test OP_EXPIRE prototype.

Test that the OP_EXPIRE works as expected.
"""


from test_framework.blocktools import (
    TIME_GENESIS_BLOCK,
    create_block,
    create_coinbase,
    NORMAL_GBT_REQUEST_PARAMS
)
from test_framework.messages import (
    CTransaction,
    SEQUENCE_FINAL,
    msg_block,
    tx_from_hex
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    CScriptNum,
    OP_1NEGATE,
    OP_EXPIRE,
    OP_DROP,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)

# Helper function to modify a transaction by
# 1) prepending a given script to the scriptSig of vin 0 and
# 2) (optionally) modify the nSequence of vin 0 and the tx's nLockTime
def expire_modify_tx(tx, prepend_scriptsig, nsequence=None, nlocktime=None, deltaHeight=None):
    assert_equal(len(tx.vin), 1)
    if nsequence is not None:
        tx.vin[0].nSequence = nsequence
        tx.nLockTime = nlocktime
        if deltaHeight is not None:
            tx.version = recalculate_version(tx, deltaHeight)

    tx.vin[0].scriptSig = CScript(prepend_scriptsig + list(CScript(tx.vin[0].scriptSig)))
    tx.rehash()

def recalculate_version(tx, deltaHeight):
    serialized_version = tx.version.to_bytes(4, "little")
    serialized_delta_height = deltaHeight.to_bytes(2, "little")
    high_bytes_int = int.from_bytes(serialized_version[2:4], "little")
    new_high_bytes_int = high_bytes_int + deltaHeight
    new_high_bytes_int &= 0xffff
    new_high_bytes = new_high_bytes_int.to_bytes(2, "little")
    new_version_bytes = serialized_version[:2] + new_high_bytes
    return int.from_bytes(new_version_bytes, "little")


def invalidate(tx, failure_reason):
    # Modify the signature in vin 0 and nSequence/nLockTime/nExpiryHeight of the tx to fail
    # OP_EXPIRE
    # OP_EXPIRE can fail due the following reasons:
    # 1) the stack is empty
    # 2) the top item on the stack is less than 0
    # 3) the lock-time type of the top stack item is not height
    # 4) the lock-time type from nLockTime is not height
    # 5) the top stack item is greater than the transaction's nLockTime plus nVersion delta field
    # 6) the nSequence field of the txin is 0xffffffff (SEQUENCE_FINAL)
    assert failure_reason in range(6)
    scheme = [
        # | Script to prepend to scriptSig                    | nSequence  | nLockTime    | nVersion    |
        # +---------------------------------------------------+------------+--------------+-------------+
        [[OP_EXPIRE],                                          None,        None,             None],
        [[OP_1NEGATE, OP_EXPIRE, OP_DROP],                     None,        None,             None],
        [[CScriptNum(TIME_GENESIS_BLOCK), OP_EXPIRE, OP_DROP], 0,           0,                None],
        [[CScriptNum(100), OP_EXPIRE, OP_DROP],                0,           TIME_GENESIS_BLOCK, None],
        [[CScriptNum(100), OP_EXPIRE, OP_DROP],                0,           50,               25],
        [[CScriptNum(50),  OP_EXPIRE, OP_DROP],               SEQUENCE_FINAL, 50,            0],
    ][failure_reason]

    expire_modify_tx(tx, prepend_scriptsig=scheme[0], nsequence=scheme[1], nlocktime=scheme[2], deltaHeight=scheme[3])


class OpExpireTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.noban_tx_relay = True
        self.extra_args = [[
            '-par=1',  # Use only one script thread to get the exact reject reason for testing
            '-acceptnonstdtxn=1',  # invalidate is nonstandard
        ], [
            '-par=1',  # Use only one script thread to get the exact reject reason for testing
            '-acceptnonstdtxn=1',  # invalidate is nonstandard
        ]]
        self.setup_clean_chain = True
        self.rpc_timeout = 480

    def run_test(self):
        self.log.info("Test that OP_EXPIRE works as expected")
        peer = self.nodes[0].add_p2p_connection(P2PInterface())
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        self.generate(wallet, 10)
        self.generate(self.nodes[0], 1000)
        for i in range(6):
            self.log.info(f"Checking OP_EXPIRE failure reason {i}")
            spendtx = wallet.create_self_transfer()['tx']
            invalidate(spendtx, i)
            self.log.info(f"Invalid tx version: {spendtx.version}")
            expected_expire_reject_reason = [
                "mandatory-script-verify-flag-failed (Operation not valid with the current stack size)",
                "mandatory-script-verify-flag-failed (Negative expire time)",
                "mandatory-script-verify-flag-failed (Expire time requirement not satisfied)",
                "mandatory-script-verify-flag-failed (Expire time requirement not satisfied)",
                "mandatory-script-verify-flag-failed (Expire time requirement not satisfied)",
                "mandatory-script-verify-flag-failed (Expire time requirement not satisfied)",
            ][i]
            # rejected by the mempool
            assert_equal(
                [{
                    'txid': spendtx.hash,
                    'wtxid': spendtx.getwtxid(),
                    'allowed': False,
                    'reject-reason': expected_expire_reject_reason,
                }],
                self.nodes[0].testmempoolaccept(rawtxs=[spendtx.serialize().hex()], maxfeerate=0),
            )

        self.log.info(f"Double check that OP_EXPIRE when conditions are met is accepted")
        spendtx = wallet.create_self_transfer()['tx']
        expire_modify_tx(spendtx, [CScriptNum(100), OP_EXPIRE, OP_DROP], 0, 50, 125)
        mempool_accept = self.nodes[0].testmempoolaccept(rawtxs=[spendtx.serialize().hex()], maxfeerate=0)
        assert_equal(len(mempool_accept), 1)
        assert_equal(mempool_accept[0]['txid'], spendtx.hash)
        assert_equal(mempool_accept[0]['wtxid'], spendtx.getwtxid())
        assert_equal(mempool_accept[0]['allowed'], True)
        wallet.sign_tx(tx=spendtx)
        spendtx_raw = spendtx.serialize().hex()
        spend = tx_from_hex(spendtx_raw)
        spendtx.rehash()
        wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=spendtx_raw)
        block = create_block(tmpl=self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS), txlist=[spendtx])
        block.solve()
        assert_equal(None, self.nodes[0].submitblock(block.serialize().hex()))
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)
        assert_equal(self.nodes[1].getbestblockhash(), block.hash)




if __name__ == '__main__':
    OpExpireTest(__file__).main()
