import base64

from app.proxy import extract


def test_single_turn_scans_everything():
    body = {
        "model": "claude-opus-5",
        "messages": [{"role": "user", "content": "hello sarah@acme.com"}],
    }
    e = extract.extract(body)
    assert e.new_text == e.full_text
    assert "sarah@acme.com" in e.new_text


def test_multiturn_only_rescans_the_trailing_user_block():
    # The whole history is retransmitted every turn on both Anthropic and
    # OpenAI-shaped APIs. Re-scanning turn 1's already-adjudicated content on
    # every subsequent turn would duplicate every finding N times over a long
    # conversation — `new_text` must isolate just what's new since the last
    # assistant reply.
    body = {
        "model": "claude-opus-5",
        "messages": [
            {"role": "user", "content": "first turn, AKIAIOSFODNN7EXAMPLE"},
            {"role": "assistant", "content": "ok, noted"},
            {"role": "user", "content": "second turn, unrelated question"},
        ],
    }
    e = extract.extract(body)
    assert "AKIAIOSFODNN7EXAMPLE" not in e.new_text
    assert "second turn" in e.new_text
    # Full history still available for the council's cross-turn context.
    assert "AKIAIOSFODNN7EXAMPLE" in e.full_text


def test_content_block_list_with_text_blocks():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": "block-shaped content"}],
            }
        ]
    }
    e = extract.extract(body)
    assert "block-shaped content" in e.new_text


def test_redaction_writes_back_in_place():
    body = {
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "email sarah@acme.com now"}]}
        ]
    }
    e = extract.extract(body)
    changed = extract.apply_redactions(
        body, e.slots, {"email sarah@acme.com now": "email [PII_1_REDACTED] now"}
    )
    assert changed == 1
    assert body["messages"][0]["content"][0]["text"] == "email [PII_1_REDACTED] now"


def test_image_attachment_is_extracted_and_flagged_new():
    img = base64.b64encode(b"not-really-a-png").decode()
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "what does this show?"},
                    {
                        "type": "image",
                        "source": {"type": "base64", "media_type": "image/png", "data": img},
                    },
                ],
            }
        ]
    }
    e = extract.extract(body)
    assert len(e.attachments) == 1
    a = e.attachments[0]
    assert a.kind == "image"
    assert a.inspectable is True
    assert a.is_new is True
    assert e.new_attachments == e.attachments


def test_unsupported_media_type_is_not_inspectable():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/zip",
                            "data": base64.b64encode(b"PK\x03\x04").decode(),
                        },
                    }
                ],
            }
        ]
    }
    e = extract.extract(body)
    assert len(e.attachments) == 1
    assert e.attachments[0].inspectable is False
    assert e.attachments[0].block is None


def test_attachment_in_older_turn_is_not_new():
    img = base64.b64encode(b"old-image-bytes").decode()
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": img}}
                ],
            },
            {"role": "assistant", "content": "I see a diagram."},
            {"role": "user", "content": "what about the colors?"},
        ]
    }
    e = extract.extract(body)
    assert len(e.attachments) == 1
    assert e.attachments[0].is_new is False
    assert e.new_attachments == []
