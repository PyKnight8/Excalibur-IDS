import unittest

from excalibur.helper.protocol import ProtocolError, decode_request, encode_response


class HelperProtocolTest(unittest.TestCase):
    def test_decode_request_accepts_sensor_status(self):
        payload = decode_request(b'{"action":"sensor_status"}')

        self.assertEqual(payload["action"], "sensor_status")

    def test_decode_request_accepts_sensor_start_and_stop(self):
        self.assertEqual(decode_request(b'{"action":"sensor_start"}')["action"], "sensor_start")
        self.assertEqual(decode_request(b'{"action":"sensor_stop"}')["action"], "sensor_stop")

    def test_decode_request_rejects_unknown_action(self):
        with self.assertRaises(ProtocolError):
            decode_request(b'{"action":"something_else"}')

    def test_decode_request_rejects_extra_fields(self):
        with self.assertRaises(ProtocolError):
            decode_request(b'{"action":"sensor_restart","service":"ssh.service"}')

    def test_decode_request_rejects_oversized_payload(self):
        with self.assertRaises(ProtocolError):
            decode_request(b"a" * 4097)

    def test_encode_response_appends_newline(self):
        encoded = encode_response({"ok": True})

        self.assertTrue(encoded.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
