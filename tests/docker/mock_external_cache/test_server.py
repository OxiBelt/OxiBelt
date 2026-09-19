import base64
import json
import time
import unittest

import server


class DictionaryStorageTests(unittest.TestCase):
  def setUp(self):
    with server.LOCK:
      server.DICTIONARY_STATE.clear()

  def exchange(self, operation, key="dictionary:one", **fields):
    request = {
      "capability": server.DICTIONARY_CAPABILITY,
      "operation": operation,
      "key": key,
      "expected_base64": None,
      "value_base64": None,
      "ttl_ms": None,
    }
    request.update(fields)
    return json.loads(server.dictionary_storage_response(json.dumps(request).encode("utf-8")))

  def test_dictionary_storage_read_compare_exchange_write_and_delete(self):
    self.assertIsNone(self.exchange("read")["value_base64"])

    value = base64.b64encode(b"dictionary").decode("ascii")
    self.exchange("compare_exchange", key="manifest", value_base64=value)
    self.assertTrue(self.exchange("write_if_manifest_matches", manifest_key="manifest", expected_base64=value, value_base64=value, ttl_ms=1_000)["matched"])
    self.assertEqual(self.exchange("read")["value_base64"], value)

    self.assertFalse(
      self.exchange(
        "compare_exchange",
        expected_base64=base64.b64encode(b"other").decode("ascii"),
        value_base64=base64.b64encode(b"replacement").decode("ascii"),
      )["matched"]
    )
    replacement = base64.b64encode(b"replacement").decode("ascii")
    self.assertTrue(
      self.exchange(
        "compare_exchange", expected_base64=value, value_base64=replacement
      )["matched"]
    )
    self.assertEqual(self.exchange("read")["value_base64"], replacement)
    self.assertTrue(self.exchange("delete")["matched"])
    self.assertIsNone(self.exchange("read")["value_base64"])

  def test_dictionary_storage_expires_values_and_rejects_invalid_keys(self):
    value = base64.b64encode(b"dictionary").decode("ascii")
    self.exchange("compare_exchange", key="manifest", value_base64=value)
    self.exchange("write_if_manifest_matches", key="dictionary:ttl", manifest_key="manifest", expected_base64=value, value_base64=value, ttl_ms=1)
    with server.LOCK:
      server.DICTIONARY_STATE["dictionary:ttl"] = (b"dictionary", time.monotonic() - 1)
    self.assertIsNone(self.exchange("read", key="dictionary:ttl")["value_base64"])

    with self.assertRaises(ValueError):
      self.exchange("read", key="invalid/key")

  def test_late_write_cannot_recreate_chunk_after_manifest_fence_and_gc(self):
    pending = base64.b64encode(b"pending").decode("ascii")
    reclaimed = base64.b64encode(b"reclaimed").decode("ascii")
    chunk = base64.b64encode(b"chunk").decode("ascii")
    self.exchange("compare_exchange", key="manifest", value_base64=pending)
    self.assertTrue(self.exchange("write_if_manifest_matches", manifest_key="manifest", expected_base64=pending, value_base64=chunk, ttl_ms=1000)["matched"])
    self.exchange("compare_exchange", key="manifest", expected_base64=pending, value_base64=reclaimed)
    self.exchange("delete")
    self.assertFalse(self.exchange("write_if_manifest_matches", manifest_key="manifest", expected_base64=pending, value_base64=chunk, ttl_ms=1000)["matched"])
    self.assertIsNone(self.exchange("read")["value_base64"])

  def test_unfenced_write_is_not_supported(self):
    with self.assertRaises(ValueError):
      self.exchange("write", value_base64=base64.b64encode(b"bad").decode("ascii"), ttl_ms=1000)


if __name__ == "__main__":
  unittest.main()
