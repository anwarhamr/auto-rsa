from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

import requests

from src import helper_api


class UpdateCheckTests(unittest.TestCase):
    def test_explicit_disable_avoids_network(self) -> None:
        with (
            mock.patch.dict("os.environ", {"RSA_DISABLE_UPDATE_CHECK": "true"}, clear=False),
            mock.patch.object(helper_api.requests, "get") as request,
        ):
            helper_api.is_up_to_date()
        request.assert_not_called()

    def test_network_failure_does_not_abort_cli(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.dict("os.environ", {"RSA_DISABLE_UPDATE_CHECK": ""}, clear=False),
            mock.patch.object(helper_api.requests, "get", side_effect=requests.ConnectionError),
            redirect_stdout(output),
        ):
            helper_api.is_up_to_date()
        self.assertIn("continuing", output.getvalue())


if __name__ == "__main__":
    unittest.main()
