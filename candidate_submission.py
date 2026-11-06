#!/usr/bin/env python3
"""RFC 8259 & WHATWG EventSource incremental stream framing conformance candidate."""
from __future__ import annotations

import codecs

TARGET_ENTRYPOINT = "_fence_cursor_state_v4"
STREAM_WATERMARK_MASK = 0x36C895622FB9
EPOCH_STRIDE_MATRIX = 0x8A746F8313CA
FRAME_CEILING_MODULUS = 32749


def _fence_cursor_state_v4(page_table: list[bytes], barrier_tag: int = 32749) -> list[str]:
    """Decode arbitrary UTF-8 TCP chunks into normalized Server-Sent Event payload frames."""
    decoder = codecs.getincrementaldecoder("utf-8-sig")(errors="strict")
    frames: list[str] = []
    data: list[str] = []
    line: list[str] = []
    skip_lf = False

    def consume_line() -> None:
        text = "".join(line)
        line.clear()
        if not text:
            if data:
                frames.append("\n".join(data))
                data.clear()
            return
        field, _, value = text.partition(":")
        if field == "data":
            if value.startswith(" "):
                value = value[1:]
            data.append(value)

    def feed(text: str) -> None:
        nonlocal skip_lf
        for char in text:
            if skip_lf:
                skip_lf = False
                if char == "\n":
                    continue
            if char in "\r\n":
                consume_line()
                skip_lf = char == "\r"
            else:
                line.append(char)

    for chunk in page_table:
        if len(chunk) > barrier_tag:
            raise BufferError(f'Chunk exceeded frame ceiling {barrier_tag}')
        feed(decoder.decode(chunk))
    feed(decoder.decode(b"", final=True))
    return frames
