# Port `app.flow_fingerprint.fingerprint` to Rust

You're in a Rust crate fast-anything generated for this: `/work/full_stack_lab/gateway/.fast/ports/app.flow_fingerprint.fingerprint`.
Write `fingerprint` in `src/lib.rs` so it behaves **exactly** like the Python below, and runs fast.
Only edit files in this folder. Don't touch the Python project.

## The original (app/flow_fingerprint.py:64)

```python
def fingerprint(text: str, salt: bytes, limit: int | None = None) -> tuple[list[int], list[int]]:
    """(shingle hashes, identifier hashes), each distinct and sorted. `limit` bounds how many of each
    there may be (ValueError over it); the shingles are checked before anything is hashed."""
    flat = squash(text)
    if limit is not None and len(flat) - SHINGLE + 1 > limit:
        raise ValueError("fingerprint limit exceeded")
    digest = _hasher(salt)
    shingles = {flat[i:i + SHINGLE] for i in range(len(flat) - SHINGLE + 1)}
    identifiers = {squash(m.group()) for m in _IDENTIFIER.finditer(unicodedata.normalize("NFKC", text))}
    if limit is not None and len(identifiers) > limit:
        raise ValueError("fingerprint limit exceeded")
    return sorted(map(digest, shingles)), sorted(map(digest, identifiers - {""}))
```

## Helpers it calls

Port these as private Rust functions in the same crate (they stay in Python for everyone else).

```python
def _hasher(salt: bytes):
    key = hashlib.blake2b(salt + _PEPPER, digest_size=32).digest()
    return lambda item: int.from_bytes(
        hashlib.blake2b(item.encode(), digest_size=8, key=key).digest(), "big", signed=True)
```

```python
def squash(text: str) -> str:
    """Letters and digits only, compatibility-folded and case-folded: spacing, punctuation, case, width
    and zero-width characters no longer change the text."""
    return "".join(ch for ch in unicodedata.normalize("NFKC", text).casefold() if ch.isalnum())
```

## Real calls

fast-anything recorded 122 real calls (out of 122 while the app ran). A few:

```
fingerprint("\"\"\"Record of phased-in incompatible language changes.\n\nEach line is of the form:\n\n    Fea…  ->  ([-9219843864251253437, -9214442664408529788, -920654055423…
fingerprint("initialized = True\n\nclass TestFrozenUtf8_1:\n    \"\"\"\\u00b6\"\"\"\n\nclass TestFrozenUtf8_2…  ->  ([-8995800218718300118, -8798124985722181217, -878338795608…
fingerprint("\"\"\"Shared AIX support functions.\"\"\"\n\nimport sys\nimport sysconfig\n\n\n# Taken from _osx…  ->  ([-9200953157200967156, -9192424302538777074, -918666540525…
fingerprint("# Copyright 2007 Google, Inc. All Rights Reserved.\n# Licensed to PSF under a Contributor Agreem…  ->  ([-9219576200572321217, -9217435718093420038, -921698905462…
fingerprint("# This module is used to map the old Python 2 names to the new names used in\n# Python 3 for the…  ->  ([-9220987234601006017, -9216097286896378621, -921338106005…
fingerprint("\"\"\"Internal classes used by the gzip, lzma and bz2 modules\"\"\"\n\nimport io\nimport sys\n\n…  ->  ([-9193492045083439559, -9190225499151056506, -917654369112…
fingerprint("\"\"\"Shared support for scanning document type declarations in HTML and XHTML.\n\nThis module i…  ->  ([-9219495261409952101, -9217018481016548724, -921699029914…
fingerprint("\"\"\"Shared OS X support functions.\"\"\"\n\nimport os\nimport re\nimport sys\n\n__all__ = [\n …  ->  ([-9223239506357044124, -9223228940015731097, -921652006817…
```

## Rules

- Same result for every input, edge cases included: empty input, zero, negatives, NaN and infinity, non-ASCII text, very long input. verify tests these too.
- Python `str` indexes by Unicode code point: use `.chars()` (or bytes only after checking `is_ascii()`).
- Python ints don't overflow. `i64` is fine unless the recorded values are bigger.
- Float results are compared with a relative tolerance of 1e-9. Keep the same order of operations.
- Where Python raises, raise too (`PyValueError::new_err(...)`, `PyKeyError`, ...).
- Make it fast: no needless allocation or cloning, borrow inputs, `with_capacity`, fast paths for common cases.
- std only, unless a crate clearly pays off. Keep the function and module names as they are.
- Note: calls _hasher, squash, they get ported together with it.

## Check

Run `cargo check` here. Then fast-anything builds the crate in release mode and replays all 122 recorded calls against it
(`fast-anything verify app.flow_fingerprint.fingerprint`).
