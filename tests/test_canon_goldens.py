"""Every willow-mcp byte family, pinned at the call site (flatten-2 F7).

The expected values below were taken from the code BEFORE it was repointed at
the one script's ``canon`` (D-e: bytes already persisted never change). They
are literals on purpose: if one moves, a persisted chain or a signature moved.
Each id names the site; the family is in ``onescript/canon.py``.
"""

from __future__ import annotations

import decimal

import pytest

# The call sites reach the one script lazily; the suite runs with it beside
# (ONESCRIPT_HOME in CI), so these exercise the repointed path.
from willow_mcp import attribution_ledger as al
from willow_mcp import bound_receipt as br
from willow_mcp import constitutional as co
from willow_mcp import dispatch_signing as ds
from willow_mcp import egress_authorization as eg
from willow_mcp import envelope_authoring as ea
from willow_mcp import governance_ledger as gl
from willow_mcp import manifest_grant_executor as mg
from willow_mcp import net_signer as ns
from willow_mcp import receipts as rc
from willow_mcp import session_binder as sb
from willow_mcp import session_signing as ss
from willow_mcp import training_corpus as tc
from willow_mcp import trust_owner_verbs as tv
from willow_mcp.subject_consent import core as sc

NA = {"name": "héllo ☃ 日本", "k": "\U0001d11e", "e": ""}
NEST = {"z": {"y": [1, 2, {"b": None, "a": True}], "x": ""}, "a": [], "n": -0.5}
ORD = {"b": 1, "a": 2, "B": 3, "é": 4, "10": 5, "9": 6}
CASES = {
    "ascii": {"b": 1, "a": "x", "permissions": ["z", "a"], "app_id": "app"},
    "nonascii": {"app_id": "ä☃", "permissions": ["é", "a", "a"], "d": NA},
    "nested": {"app_id": "n", "permissions": [], "d": NEST},
    "empty": {},
    "order": dict(ORD, permissions=["q"]),
}
HDR = {k: ("é☃" if i == 0 else f"v{i}") for i, k in enumerate(sb._SIGNED_FIELDS)}
PAYLOAD = {
    "agent_identity_ref": "a☃", "capability_token_ref": "c", "policy_or_manifest_digest": "p",
    "tool_call_digest": "t", "effect_ref_or_denial_code": "e", "ledger_prev": "lp",
    "ledger_entry_hash": "le", "signer_id": "sé", "issued_at": "i", "expires_at": "x",
}

GOLDEN = [
    ('manifest_policy_digest/ascii', lambda: br.manifest_policy_digest(CASES['ascii']), '2e8d14d9ea84d8382389d99b3c910c908f70ec9a3d8869244cb27fd85eae9fd7'),
    ('manifest_acl_digest/ascii', lambda: br.manifest_acl_digest(CASES['ascii']), 'd336562589900fc58de6d070ba979fed2a96186568bf2a2ad619e79c9583d53b'),
    ('bounds_digest/ascii', lambda: ea._bounds_digest(CASES['ascii']), '2e8d14d9ea84d8382389d99b3c910c908f70ec9a3d8869244cb27fd85eae9fd7'),
    ('egress_canonical_payload/ascii', lambda: eg._canonical_payload(CASES['ascii']), b'{"a":"x","app_id":"app","b":1,"permissions":["z","a"]}'),
    ('proposal_digest/ascii', lambda: tv._proposal_digest(CASES['ascii']), '62ee8323035a8533359b86ce905213666870bdf33b93bb46566aadf141eaa6d9'),
    ('dispatch_canonical/ascii', lambda: ds._canonical_bytes(CASES['ascii']), b'{"a":"x","app_id":"app","b":1,"permissions":["z","a"]}'),
    ('grant_request_bytes/ascii', lambda: mg._canonical_request_bytes(CASES['ascii']), b'{"apps":null,"citation_id":null,"envelope_id":null,"groups":null,"pair_id":null,"pre_state":null,"requested_at":null,"sealed_row":null}'),
    ('consent_canonical/ascii', lambda: sc._canonical(CASES['ascii']), b'{"a":"x","app_id":"app","b":1,"permissions":["z","a"]}'),
    ('training_canonical/ascii', lambda: tc._canonical(CASES['ascii']), '{"a":"x","app_id":"app","b":1,"permissions":["z","a"]}'),
    ('constitutional_canonical/ascii', lambda: co._canonical_json(CASES['ascii']), '{"a":"x","app_id":"app","b":1,"permissions":["z","a"]}'),
    ('governance_payload/ascii', lambda: gl._payload('ev', CASES['ascii']), '{"content": {"a": "x", "app_id": "app", "b": 1, "permissions": ["z", "a"]}, "event_type": "ev"}'),
    ('governance_payload_v2/ascii', lambda: gl._payload_v2('i', 'p', 'ev', CASES['ascii']), '{"content": {"a": "x", "app_id": "app", "b": 1, "permissions": ["z", "a"]}, "event_type": "ev", "id": "i", "project": "p"}'),
    ('governance_hash_v2/ascii', lambda: gl.entry_hash_v2('prev', 'i', 'p', 'ev', CASES['ascii']), 'a8e06cb4c73ad9ac44f2244ad222206aa8ddd7f1f0c10a822a7fed76b970f282'),
    ('governance_hash_v1/ascii', lambda: gl.entry_hash('prev', 'ev', CASES['ascii']), 'ca64eba6cba387e5894a23cc362ef094fe94e7fb72268f48b97856684e096bc1'),
    ('manifest_policy_digest/nonascii', lambda: br.manifest_policy_digest(CASES['nonascii']), 'b2b76745de4bee676e9bdd0f38b264f81992f3423fc63b08024b5f31ea8b63cb'),
    ('manifest_acl_digest/nonascii', lambda: br.manifest_acl_digest(CASES['nonascii']), '9a927e2119370536b90eeccaa3bc35d162b47e3a63c11f9050e568f2c1a1d40f'),
    ('bounds_digest/nonascii', lambda: ea._bounds_digest(CASES['nonascii']), 'b2b76745de4bee676e9bdd0f38b264f81992f3423fc63b08024b5f31ea8b63cb'),
    ('egress_canonical_payload/nonascii', lambda: eg._canonical_payload(CASES['nonascii']), b'{"app_id":"\xc3\xa4\xe2\x98\x83","d":{"e":"","k":"\xf0\x9d\x84\x9e","name":"h\xc3\xa9llo \xe2\x98\x83 \xe6\x97\xa5\xe6\x9c\xac"},"permissions":["\xc3\xa9","a","a"]}'),
    ('proposal_digest/nonascii', lambda: tv._proposal_digest(CASES['nonascii']), '62ee8323035a8533359b86ce905213666870bdf33b93bb46566aadf141eaa6d9'),
    ('dispatch_canonical/nonascii', lambda: ds._canonical_bytes(CASES['nonascii']), b'{"app_id":"\\u00e4\\u2603","d":{"e":"","k":"\\ud834\\udd1e","name":"h\\u00e9llo \\u2603 \\u65e5\\u672c"},"permissions":["\\u00e9","a","a"]}'),
    ('grant_request_bytes/nonascii', lambda: mg._canonical_request_bytes(CASES['nonascii']), b'{"apps":null,"citation_id":null,"envelope_id":null,"groups":null,"pair_id":null,"pre_state":null,"requested_at":null,"sealed_row":null}'),
    ('consent_canonical/nonascii', lambda: sc._canonical(CASES['nonascii']), b'{"app_id":"\\u00e4\\u2603","d":{"e":"","k":"\\ud834\\udd1e","name":"h\\u00e9llo \\u2603 \\u65e5\\u672c"},"permissions":["\\u00e9","a","a"]}'),
    ('training_canonical/nonascii', lambda: tc._canonical(CASES['nonascii']), '{"app_id":"\\u00e4\\u2603","d":{"e":"","k":"\\ud834\\udd1e","name":"h\\u00e9llo \\u2603 \\u65e5\\u672c"},"permissions":["\\u00e9","a","a"]}'),
    ('constitutional_canonical/nonascii', lambda: co._canonical_json(CASES['nonascii']), '{"app_id":"\\u00e4\\u2603","d":{"e":"","k":"\\ud834\\udd1e","name":"h\\u00e9llo \\u2603 \\u65e5\\u672c"},"permissions":["\\u00e9","a","a"]}'),
    ('governance_payload/nonascii', lambda: gl._payload('ev', CASES['nonascii']), '{"content": {"app_id": "\\u00e4\\u2603", "d": {"e": "", "k": "\\ud834\\udd1e", "name": "h\\u00e9llo \\u2603 \\u65e5\\u672c"}, "permissions": ["\\u00e9", "a", "a"]}, "event_type": "ev"}'),
    ('governance_payload_v2/nonascii', lambda: gl._payload_v2('i', 'p', 'ev', CASES['nonascii']), '{"content": {"app_id": "\\u00e4\\u2603", "d": {"e": "", "k": "\\ud834\\udd1e", "name": "h\\u00e9llo \\u2603 \\u65e5\\u672c"}, "permissions": ["\\u00e9", "a", "a"]}, "event_type": "ev", "id": "i", "project": "p"}'),
    ('governance_hash_v2/nonascii', lambda: gl.entry_hash_v2('prev', 'i', 'p', 'ev', CASES['nonascii']), '0bc16ddbc05f0733d07ec2f0c1577e65ea1556385abdc812c867ad7efa84a1a1'),
    ('governance_hash_v1/nonascii', lambda: gl.entry_hash('prev', 'ev', CASES['nonascii']), 'db7dae652c5115ccad60befbb54cc9c8643237a38578cd8bc76d7c31ee2d3246'),
    ('manifest_policy_digest/nested', lambda: br.manifest_policy_digest(CASES['nested']), '3d430afb97cfb1d0f483823325ea6cf127d613ec11dfd3556c9e413a4117523e'),
    ('manifest_acl_digest/nested', lambda: br.manifest_acl_digest(CASES['nested']), '3fcfeac6e5f2137839eac9e476da4f95e89af0f9acd87df7a48a0c468951546c'),
    ('bounds_digest/nested', lambda: ea._bounds_digest(CASES['nested']), '3d430afb97cfb1d0f483823325ea6cf127d613ec11dfd3556c9e413a4117523e'),
    ('egress_canonical_payload/nested', lambda: eg._canonical_payload(CASES['nested']), b'{"app_id":"n","d":{"a":[],"n":-0.5,"z":{"x":"","y":[1,2,{"a":true,"b":null}]}},"permissions":[]}'),
    ('proposal_digest/nested', lambda: tv._proposal_digest(CASES['nested']), '62ee8323035a8533359b86ce905213666870bdf33b93bb46566aadf141eaa6d9'),
    ('dispatch_canonical/nested', lambda: ds._canonical_bytes(CASES['nested']), b'{"app_id":"n","d":{"a":[],"n":-0.5,"z":{"x":"","y":[1,2,{"a":true,"b":null}]}},"permissions":[]}'),
    ('grant_request_bytes/nested', lambda: mg._canonical_request_bytes(CASES['nested']), b'{"apps":null,"citation_id":null,"envelope_id":null,"groups":null,"pair_id":null,"pre_state":null,"requested_at":null,"sealed_row":null}'),
    ('consent_canonical/nested', lambda: sc._canonical(CASES['nested']), b'{"app_id":"n","d":{"a":[],"n":-0.5,"z":{"x":"","y":[1,2,{"a":true,"b":null}]}},"permissions":[]}'),
    ('training_canonical/nested', lambda: tc._canonical(CASES['nested']), '{"app_id":"n","d":{"a":[],"n":-0.5,"z":{"x":"","y":[1,2,{"a":true,"b":null}]}},"permissions":[]}'),
    ('constitutional_canonical/nested', lambda: co._canonical_json(CASES['nested']), '{"app_id":"n","d":{"a":[],"n":-0.5,"z":{"x":"","y":[1,2,{"a":true,"b":null}]}},"permissions":[]}'),
    ('governance_payload/nested', lambda: gl._payload('ev', CASES['nested']), '{"content": {"app_id": "n", "d": {"a": [], "n": -0.5, "z": {"x": "", "y": [1, 2, {"a": true, "b": null}]}}, "permissions": []}, "event_type": "ev"}'),
    ('governance_payload_v2/nested', lambda: gl._payload_v2('i', 'p', 'ev', CASES['nested']), '{"content": {"app_id": "n", "d": {"a": [], "n": -0.5, "z": {"x": "", "y": [1, 2, {"a": true, "b": null}]}}, "permissions": []}, "event_type": "ev", "id": "i", "project": "p"}'),
    ('governance_hash_v2/nested', lambda: gl.entry_hash_v2('prev', 'i', 'p', 'ev', CASES['nested']), 'd822a70467b3b105acbbf4a4700f8eed3fd5d862770a3b05e7980faf358ebd46'),
    ('governance_hash_v1/nested', lambda: gl.entry_hash('prev', 'ev', CASES['nested']), 'daf415bcfbef83daaaab636bb72e450babbf515e3864d6dbf8ba99f7d09a4bc8'),
    ('manifest_policy_digest/empty', lambda: br.manifest_policy_digest(CASES['empty']), '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('manifest_acl_digest/empty', lambda: br.manifest_acl_digest(CASES['empty']), '5711fd44b9870470de8788c6a8e911a3efa2f5c0f9fdf3ebaa81c9183fd6632c'),
    ('bounds_digest/empty', lambda: ea._bounds_digest(CASES['empty']), '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('egress_canonical_payload/empty', lambda: eg._canonical_payload(CASES['empty']), b'{}'),
    ('proposal_digest/empty', lambda: tv._proposal_digest(CASES['empty']), '62ee8323035a8533359b86ce905213666870bdf33b93bb46566aadf141eaa6d9'),
    ('dispatch_canonical/empty', lambda: ds._canonical_bytes(CASES['empty']), b'{}'),
    ('grant_request_bytes/empty', lambda: mg._canonical_request_bytes(CASES['empty']), b'{"apps":null,"citation_id":null,"envelope_id":null,"groups":null,"pair_id":null,"pre_state":null,"requested_at":null,"sealed_row":null}'),
    ('consent_canonical/empty', lambda: sc._canonical(CASES['empty']), b'{}'),
    ('training_canonical/empty', lambda: tc._canonical(CASES['empty']), '{}'),
    ('constitutional_canonical/empty', lambda: co._canonical_json(CASES['empty']), '{}'),
    ('governance_payload/empty', lambda: gl._payload('ev', CASES['empty']), '{"content": {}, "event_type": "ev"}'),
    ('governance_payload_v2/empty', lambda: gl._payload_v2('i', 'p', 'ev', CASES['empty']), '{"content": {}, "event_type": "ev", "id": "i", "project": "p"}'),
    ('governance_hash_v2/empty', lambda: gl.entry_hash_v2('prev', 'i', 'p', 'ev', CASES['empty']), '621899ee88cde76df361fb35f1bd6dd3213d050866b2852245148b25a469506a'),
    ('governance_hash_v1/empty', lambda: gl.entry_hash('prev', 'ev', CASES['empty']), 'fc6165f9a471ccde9042f254d9307d77294d4d49d04f688853093f2f383db7af'),
    ('manifest_policy_digest/order', lambda: br.manifest_policy_digest(CASES['order']), 'f802be97ee52f3502fcf9ddf6fe7f47f4fb59a575e5f6eccadaef4e493ca7b0d'),
    ('manifest_acl_digest/order', lambda: br.manifest_acl_digest(CASES['order']), '5507e131b32a86502cd941605c150b1ba06770ee675ecbb2e61ca4be8eff2657'),
    ('bounds_digest/order', lambda: ea._bounds_digest(CASES['order']), 'f802be97ee52f3502fcf9ddf6fe7f47f4fb59a575e5f6eccadaef4e493ca7b0d'),
    ('egress_canonical_payload/order', lambda: eg._canonical_payload(CASES['order']), b'{"10":5,"9":6,"B":3,"a":2,"b":1,"permissions":["q"],"\xc3\xa9":4}'),
    ('proposal_digest/order', lambda: tv._proposal_digest(CASES['order']), '62ee8323035a8533359b86ce905213666870bdf33b93bb46566aadf141eaa6d9'),
    ('dispatch_canonical/order', lambda: ds._canonical_bytes(CASES['order']), b'{"10":5,"9":6,"B":3,"a":2,"b":1,"permissions":["q"],"\\u00e9":4}'),
    ('grant_request_bytes/order', lambda: mg._canonical_request_bytes(CASES['order']), b'{"apps":null,"citation_id":null,"envelope_id":null,"groups":null,"pair_id":null,"pre_state":null,"requested_at":null,"sealed_row":null}'),
    ('consent_canonical/order', lambda: sc._canonical(CASES['order']), b'{"10":5,"9":6,"B":3,"a":2,"b":1,"permissions":["q"],"\\u00e9":4}'),
    ('training_canonical/order', lambda: tc._canonical(CASES['order']), '{"10":5,"9":6,"B":3,"a":2,"b":1,"permissions":["q"],"\\u00e9":4}'),
    ('constitutional_canonical/order', lambda: co._canonical_json(CASES['order']), '{"10":5,"9":6,"B":3,"a":2,"b":1,"permissions":["q"],"\\u00e9":4}'),
    ('governance_payload/order', lambda: gl._payload('ev', CASES['order']), '{"content": {"10": 5, "9": 6, "B": 3, "a": 2, "b": 1, "permissions": ["q"], "\\u00e9": 4}, "event_type": "ev"}'),
    ('governance_payload_v2/order', lambda: gl._payload_v2('i', 'p', 'ev', CASES['order']), '{"content": {"10": 5, "9": 6, "B": 3, "a": 2, "b": 1, "permissions": ["q"], "\\u00e9": 4}, "event_type": "ev", "id": "i", "project": "p"}'),
    ('governance_hash_v2/order', lambda: gl.entry_hash_v2('prev', 'i', 'p', 'ev', CASES['order']), '45c4eef02d64aebcdcf2cdf36acc52bebd8f7bf43584bdae7e3780668ae37591'),
    ('governance_hash_v1/order', lambda: gl.entry_hash('prev', 'ev', CASES['order']), '05238f1c973ab8bf672c6ed0226b9f42fd2d4496e17906330681a667caa2f4c6'),
    ('training_canonical/default_str', lambda: tc._canonical({'d': decimal.Decimal('1.5'), 'a': 1}), '{"a":1,"d":"1.5"}'),
    ('training_make_id/nonascii', lambda: tc.make_id('src', NA, {'l': 'é'}), 'tex_90cc1761c00a6b1201a3c2e6bb8882c6'),
    ('binder_header_canonical', lambda: sb._canonical(HDR), b'{"agent_id":"\\u00e9\\u2603","agent_name":"v1","drift":"v2","fail_count":"v3","last_gate":"v4","nonce":"v5","pass_count":"v6","reserved":"v7","state_hash":"v8","timestamp":"v9","tools":"v10","trust_level":"v11"}'),
    ('binder_header_sig', lambda: sb.expected_header_sig(b'k', HDR), 'e087b751a4de4abb3c0d243f21a43d8fbca316337ba3171651112967f8595fd1'),
    ('binder_call_sig/ascii', lambda: sb.call_sig(b'k','s','a','t','n'), '15e046243eb86ecd6e27b90c397ee25ef341866fa84b13edd824297770f35de2'),
    ('binder_call_sig/nonascii', lambda: sb.call_sig(b'k','s☃','a','t é','n'), '43db5a60b2beea3a95c93fa6738a5b64d559ba5f39c7fedcc4ac795c11e90604'),
    ('seal_message/nonascii', lambda: ns.seal_message('src é','tgt ☃','ver'), b'["src \xc3\xa9","tgt \xe2\x98\x83","ver"]'),
    ('seal_message/empty', lambda: ns.seal_message('','',''), b'["","",""]'),
    ('session_message/nonascii', lambda: ss._message('app','sé☃','v','2026-01-01T00:00:00Z'), b'["app","s\xc3\xa9\xe2\x98\x83","v","2026-01-01T00:00:00Z"]'),
    ('session_message/empty', lambda: ss._message('','','',''), b'["","","",""]'),
    ('agent_identity_ref', lambda: br.agent_identity_ref('agént', 3, 'sess☃'), 'ca4a74b2abb90bbe57688b6e9c658d37e57f9d80c6bb6df6400cd82a71407f32'),
    ('tool_call_digest', lambda: br.tool_call_digest('s☃','a','t','n'), 'c7f163b8759b8c7f6e1d4c40d072c66fad54a0d6f426287518de2cfdc363b956'),
    ('effect_ref/detail', lambda: br.effect_ref('ok', 'détail ☃'), 'effect:5645879c5b9e2fa35a631d22b5efaefb6b43b9339b5366ab8433257305925deb'),
    ('effect_ref/none', lambda: br.effect_ref('ok'), 'effect:36c61e509c873c4c6d59f50dfd4d000be0bf5b3d31967aaabb9b4eb82762db42'),
    ('ledger_entry_hash', lambda: br.ledger_entry_hash('p','ts','app','tool','out','dé'), 'e579d82b8dca2c4246c319cd7214eb6d269321ad86ee09839e85b126ce7670cd'),
    ('ledger_entry_hash/none', lambda: br.ledger_entry_hash('p','ts','app','tool','out',None), '94f7ffa89e91ac09ab7f6a0b6ec350afae853abee22b06ea586e8bfc51982401'),
    ('receipts_entry_hash', lambda: rc._entry_hash('p','ts','app','tool','out','dé☃'), '695db4dbeaf1d18941f2dd57962f537640bf733c50bd0a0dbcaa2b92f3b4c2b9'),
    ('receipts_entry_hash/none', lambda: rc._entry_hash('p','ts','app','tool','out',None), '94f7ffa89e91ac09ab7f6a0b6ec350afae853abee22b06ea586e8bfc51982401'),
    ('canonical_signed_bytes', lambda: br.canonical_signed_bytes(PAYLOAD), b'["willow-bound-receipt/1","a\xe2\x98\x83","c","p","t","e","lp","le","s\xc3\xa9","i","x"]'),

]


@pytest.mark.parametrize("name,fn,want", GOLDEN, ids=[g[0] for g in GOLDEN])
def test_site_bytes_are_pinned(name, fn, want):
    assert fn() == want


def test_attribution_ledger_lines_and_heads_are_pinned(tmp_path):
    p = str(tmp_path / "attr.jsonl")
    h1 = al.append("sess☃", "verifier", "2026-01-01T00:00:00Z", "digest", path=p)
    h2 = al.append("s2", "vé", "2026-01-02T00:00:00Z", "d2", path=p)
    with open(p, encoding="utf-8") as fh:
        assert fh.read() == '{"kind":"session_attestation","session_id":"sess☃","verifier":"verifier","attested_at":"2026-01-01T00:00:00Z","sig_digest":"digest","prev":"genesis"}\n{"kind":"session_attestation","session_id":"s2","verifier":"vé","attested_at":"2026-01-02T00:00:00Z","sig_digest":"d2","prev":"996f7f59a656a8851ee5e5cc2ce9ee61cbc70237dcb94cda98730d97ac7fa74b"}\n'
    assert [h1, h2] == ['996f7f59a656a8851ee5e5cc2ce9ee61cbc70237dcb94cda98730d97ac7fa74b', '3a76c7148d78f8652dee0a70fbae3f9f94ab0f769ef7684fbc5a014bb85d1d0f']


def test_consent_row_hash_is_pinned():
    c = sc.Consent(
        subject_id="sub☃", scope="scope", status="granted", granted_by="gé",
        at="2026-01-01T00:00:00Z", prev_hash="0" * 64, hash="",
    )
    assert sc._row_hash(c.payload()) == '2299a4f97e6e9d2799b1031419691df6e736e69b7f9bfcc266180e798782f225'
