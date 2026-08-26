import blockchain_ledger
import os
import tempfile

def test_full_pipeline():
    print("=== TEST 1: Idempotent Setup ===")
    priv1, pub1, is_new1 = blockchain_ledger.load_or_generate_keypair()
    print(f"   First call:  pub={pub1[:16]}..., is_new={is_new1}")
    
    priv2, pub2, is_new2 = blockchain_ledger.load_or_generate_keypair()
    print(f"   Second call: pub={pub2[:16]}..., is_new={is_new2}")
    
    assert pub1 == pub2, "Public keys must match across calls (idempotency)"
    assert priv1 == priv2, "Private keys must match across calls (idempotency)"
    assert is_new2 is False, "Second call must NOT flag as newly generated"
    print("   [PASS] Idempotent setup passed.")

    print("\n=== TEST 2: Ephemeral Key Generation ===")
    priv, pub = blockchain_ledger.generate_keypair()
    print(f"   Public Key:  {pub}")
    print(f"   Private Key: {priv[:16]}... ({len(priv)} chars)")

    print("\n=== TEST 3: Create Genesis Block ===")
    disk_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    genesis = blockchain_ledger.create_genesis(disk_hash, pub, priv)
    assert genesis["block_index"] == 0
    assert genesis["prev_hash"] == "0" * 64
    assert genesis["block_type"] == "genesis"
    assert genesis["payload"]["disk_baseline_sha256"] == disk_hash
    assert genesis["payload"]["operator_public_key"] == pub
    print("   [PASS] Genesis block created & schema validated.")

    print("\n=== TEST 4: Log 3 Recovery Stages ===")
    # Stage 1: metadata_only
    b1 = blockchain_ledger.log_action(
        "metadata_only",
        {
            "filename": "suspicious_doc.pdf",
            "macb_timestamps": {
                "modified": "2026-08-20T10:15:30Z",
                "accessed": "2026-08-21T08:00:00Z",
                "created": "2026-08-19T14:22:10Z"
            },
            "recovery_method": "mft_carving"
        },
        "file_001",
        genesis,
        priv
    )
    assert b1["block_index"] == 1
    assert b1["prev_hash"] == genesis["block_hash"]
    assert b1["block_type"] == "metadata_only"
    print("   [PASS] Stage 1 (metadata_only) logged.")

    # Stage 2: data_only
    b2 = blockchain_ledger.log_action(
        "data_only",
        {
            "recovered_file_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "source_location": "sector_0x1A400_offset_512",
            "size": 65536,
            "recovery_method": "header_footer_carver"
        },
        "file_002",
        b1,
        priv
    )
    assert b2["block_index"] == 2
    assert b2["prev_hash"] == b1["block_hash"]
    assert b2["block_type"] == "data_only"
    print("   [PASS] Stage 2 (data_only) logged.")

    # Stage 3: full_recovery
    b3 = blockchain_ledger.log_action(
        "full_recovery",
        {
            "filename": "suspicious_doc.pdf",
            "macb_timestamps": {
                "modified": "2026-08-20T10:15:30Z",
                "accessed": "2026-08-21T08:00:00Z",
                "created": "2026-08-19T14:22:10Z"
            },
            "recovered_file_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "size": 65536,
            "source_location": "sector_0x1A400_offset_512",
            "recovery_method": "mft_plus_carver"
        },
        "file_003",
        b2,
        priv
    )
    assert b3["block_index"] == 3
    assert b3["prev_hash"] == b2["block_hash"]
    assert b3["block_type"] == "full_recovery"
    print("   [PASS] Stage 3 (full_recovery) logged.")

    chain = [genesis, b1, b2, b3]

    print("\n=== TEST 5: Verify Clean Chain ===")
    res = blockchain_ledger.verify_chain(chain, pub)
    assert res["valid"] is True
    assert res["broken_at_index"] is None
    assert res["reason"] is None
    print(f"   [PASS] Clean chain verification: valid={res['valid']}")

    print("\n=== TEST 6: Payload Schema Rejection on Missing Fields ===")
    try:
        blockchain_ledger.log_action(
            "metadata_only",
            {"filename": "incomplete.txt"},  # missing macb_timestamps and recovery_method
            "file_bad",
            b3,
            priv
        )
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"   [PASS] Successfully caught expected error: {e}")

    print("\n=== TEST 7: Tamper Detection ===")
    tampered_chain = [genesis, b1, dict(b2), b3]
    tampered_chain[2]["payload"] = {
        "recovered_file_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "source_location": "sector_0x1A400_offset_512",
        "size": 999999,  # tampered size
        "recovery_method": "header_footer_carver"
    }
    res_tampered = blockchain_ledger.verify_chain(tampered_chain, pub)
    assert res_tampered["valid"] is False
    assert res_tampered["broken_at_index"] == 2
    assert "hash mismatch" in res_tampered["reason"]
    print(f"   [PASS] Tampered chain detected: broken_at_index={res_tampered['broken_at_index']}, reason={res_tampered['reason']}")

    print("\n=== TEST 8: JSONL Append & Load Roundtrip ===")
    tmp_file = os.path.join(tempfile.gettempdir(), "test_forensic_chain_e2e.jsonl")
    if os.path.exists(tmp_file):
        os.remove(tmp_file)

    for block in chain:
        blockchain_ledger.append_block(block, tmp_file)

    loaded_chain = blockchain_ledger.load_chain(tmp_file)
    assert len(loaded_chain) == 4
    for orig, loaded in zip(chain, loaded_chain):
        assert orig["block_hash"] == loaded["block_hash"]
        assert orig["signature"] == loaded["signature"]
        assert orig["payload"] == loaded["payload"]
        assert orig["public_key_id"] == loaded["public_key_id"]
    print(f"   [PASS] Successfully wrote {len(chain)} blocks and reloaded them identically from JSONL.")

    print("\n=======================================================")
    print("  ALL 8 PIPELINE & SETUP TESTS PASSED SUCCESSFULLY!")
    print("=======================================================")

if __name__ == "__main__":
    test_full_pipeline()
