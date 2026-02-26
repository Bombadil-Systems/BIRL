"""
BIRL UTF-8 Context

Interprets bytes as UTF-8 text. Coverage indicates what fraction
of the byte sequence constitutes valid UTF-8 sequences.

Interesting for BIRL because:
- Almost any ASCII text is valid UTF-8 (high coincidental coverage)
- Binary files often have pockets of valid UTF-8 (strings)
- Overlong encodings are a classic interpretation boundary attack
"""

from __future__ import annotations

from birl.context import Context, ValidityTuple, StructuredRange


class UTF8_Context(Context):

    @property
    def name(self) -> str:
        return "UTF8"

    @property
    def threshold(self) -> float:
        return 0.9  # Text files should be nearly 100% valid UTF-8

    def parse(self, data: bytes) -> ValidityTuple:
        ranges: list[StructuredRange] = []
        errors: list[str] = []
        identity: dict = {}

        if not data:
            return ValidityTuple(False, 0.0, (), errors=("Empty",))

        # Walk the bytes and identify valid UTF-8 sequences
        valid_runs: list[tuple[int, int]] = []
        invalid_runs: list[tuple[int, int]] = []
        i = 0
        current_valid_start = 0
        total_valid = 0
        is_in_valid = True

        while i < len(data):
            byte = data[i]
            seq_len = 0

            if byte <= 0x7F:
                seq_len = 1
            elif 0xC2 <= byte <= 0xDF:
                seq_len = 2
            elif 0xE0 <= byte <= 0xEF:
                seq_len = 3
            elif 0xF0 <= byte <= 0xF4:
                seq_len = 4
            else:
                # Invalid lead byte (includes overlong C0-C1)
                if is_in_valid and i > current_valid_start:
                    valid_runs.append((current_valid_start, i))
                    total_valid += i - current_valid_start
                is_in_valid = False
                i += 1
                continue

            # Verify continuation bytes
            valid_seq = True
            if i + seq_len > len(data):
                valid_seq = False
            else:
                for j in range(1, seq_len):
                    if not (0x80 <= data[i + j] <= 0xBF):
                        valid_seq = False
                        break

            if valid_seq:
                if not is_in_valid:
                    current_valid_start = i
                    is_in_valid = True
                i += seq_len
            else:
                if is_in_valid and i > current_valid_start:
                    valid_runs.append((current_valid_start, i))
                    total_valid += i - current_valid_start
                is_in_valid = False
                i += 1

        # Flush final valid run
        if is_in_valid and i > current_valid_start:
            valid_runs.append((current_valid_start, i))
            total_valid += i - current_valid_start

        # Build structured ranges from valid runs
        for idx, (start, end) in enumerate(valid_runs):
            ranges.append(StructuredRange(
                start, end, f"utf8_run_{idx}",
                f"Valid UTF-8 sequence ({end - start} bytes)",
            ))

        coverage = total_valid / len(data) if data else 0.0
        fully_valid = coverage > 0.99

        # Attempt full decode for identity
        if fully_valid:
            try:
                text = data.decode("utf-8")
                identity["text"] = text
                identity["char_count"] = len(text)
                identity["line_count"] = text.count("\n") + 1
            except UnicodeDecodeError:
                fully_valid = False

        # Penalize coverage for binary indicators: high ratio of control chars
        # (except common text ones: \t, \n, \r) suggests this isn't really text
        control_count = sum(
            1 for b in data
            if b < 0x20 and b not in (0x09, 0x0A, 0x0D)  # tab, newline, carriage return
        )
        control_ratio = control_count / len(data) if data else 0.0
        # If >10% control chars, this is almost certainly binary, not text
        # Scale coverage down proportionally
        adjusted_coverage = coverage * max(0.0, 1.0 - (control_ratio * 5.0))

        identity["valid_byte_ratio"] = coverage
        identity["adjusted_coverage"] = adjusted_coverage
        identity["control_char_ratio"] = control_ratio
        identity["num_valid_runs"] = len(valid_runs)

        return ValidityTuple(
            valid=adjusted_coverage > 0.5,
            coverage=adjusted_coverage,
            structured_ranges=tuple(ranges),
            identity=identity,
            errors=tuple(errors),
        )
