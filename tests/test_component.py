import os
import unittest
from os import path
from os.path import dirname
import hashlib

import mock
from freezegun import freeze_time

from src.component import Component

TEST_DIR = path.join(dirname(path.realpath(__file__)), "test_data")
TEST_DIR_TIMESTAMP = path.join(dirname(path.realpath(__file__)), "test_data_timestamp")
TEST_DIR_FTP = path.join(dirname(path.realpath(__file__)), "e2e_configs", "ftp")
TEST_DIR_SFTP = path.join(dirname(path.realpath(__file__)), "e2e_configs", "sftp")
EXPECTED_SERVER_DATA = path.join(dirname(path.realpath(__file__)), "expected_server_data")


class TestComponent(unittest.TestCase):
    @mock.patch.dict(os.environ, {"KBC_DATADIR": TEST_DIR})
    def setUp(self):
        self.comp = Component()

    # set global time to 2010-10-10 - affects functions like datetime.now()
    @freeze_time("2010-10-10")
    # set KBC_DATADIR env to non-existing dir
    @mock.patch.dict(os.environ, {"KBC_DATADIR": "./non-existing-dir"})
    def test_run_no_cfg_fails(self):
        with self.assertRaises(ValueError):
            comp = Component()
            comp.run()

    @freeze_time("2010-10-10")
    def test_get_output_destination(self):
        input_table = self.comp.get_input_tables_definitions()[0]
        output_destination = self.comp.get_output_destination(input_table)
        self.assertEqual(output_destination, "/path/test_20101010000000.csv")

    @freeze_time("2010-10-10")
    @mock.patch.dict(os.environ, {"KBC_DATADIR": TEST_DIR_TIMESTAMP})
    def test_get_output_destination_custom(self):
        comp = Component()
        input_table = comp.get_input_tables_definitions()[0]
        output_destination = comp.get_output_destination(input_table)
        self.assertEqual(output_destination, "/path/test_2010-10-10-00:00:00.csv")

    def test_get_private_key_with_none(self):
        key = self.comp.get_private_key()
        self.assertEqual(key, None)


class E2ETestComponent(unittest.TestCase):
    @mock.patch.dict(os.environ, {"KBC_DATADIR": TEST_DIR_FTP})
    def test_e2e_ftp(self):
        self.comp = Component()
        self.comp.run()
        source_table_path = self.comp.get_input_tables_definitions()[0].full_path
        dest_path = path.join(EXPECTED_SERVER_DATA, "ftp", "test.csv")
        self.assertTrue(os.path.exists(dest_path))

        with open(dest_path, "rb") as dest, open(source_table_path, "rb") as src:
            src_md5 = hashlib.md5(src.read()).hexdigest()
            dest_md5 = hashlib.md5(dest.read()).hexdigest()
            self.assertEqual(src_md5, dest_md5)

    @mock.patch.dict(os.environ, {"KBC_DATADIR": TEST_DIR_SFTP})
    def test_e2e_sftp(self):
        self.comp = Component()
        self.comp.run()
        source_table_path = self.comp.get_input_tables_definitions()[0].full_path
        dest_path = path.join(EXPECTED_SERVER_DATA, "sftp", "test.csv")
        self.assertTrue(os.path.exists(dest_path))

        with open(dest_path, "rb") as dest, open(source_table_path, "rb") as src:
            src_md5 = hashlib.md5(src.read()).hexdigest()
            dest_md5 = hashlib.md5(dest.read()).hexdigest()
            self.assertEqual(src_md5, dest_md5)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
