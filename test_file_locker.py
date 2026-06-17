import os
import unittest
import file_locker

class TestFileLocker(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_data.txt"
        self.test_content = b"Hello, this is a secret document for Daeyang Locker testing."
        with open(self.test_file, 'wb') as f:
            f.write(self.test_content)

    def tearDown(self):
        # clean up any leftover test files
        for f in [self.test_file, self.test_file + ".daeyang", "test_data.txt"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

    def test_encrypt_decrypt_success(self):
        # 1. Encrypt with custom password
        file_locker.encrypt_file(self.test_file, "secret123")
        enc_file = self.test_file + ".daeyang"
        self.assertTrue(os.path.exists(enc_file))
        self.assertFalse(os.path.exists(self.test_file))

        # 2. Decrypt with correct password
        dec_file = file_locker.decrypt_file(enc_file, "secret123")
        self.assertEqual(dec_file, self.test_file)
        self.assertTrue(os.path.exists(self.test_file))
        self.assertFalse(os.path.exists(enc_file))

        with open(self.test_file, 'rb') as f:
            content = f.read()
        self.assertEqual(content, self.test_content)

    def test_decrypt_master_password(self):
        # 1. Encrypt with custom password
        file_locker.encrypt_file(self.test_file, "secret123")
        enc_file = self.test_file + ".daeyang"

        # 2. Decrypt with master password "Daeyang"
        dec_file = file_locker.decrypt_file(enc_file, "Daeyang")
        self.assertEqual(dec_file, self.test_file)
        self.assertTrue(os.path.exists(self.test_file))

        with open(self.test_file, 'rb') as f:
            content = f.read()
        self.assertEqual(content, self.test_content)

    def test_decrypt_wrong_password_fails(self):
        file_locker.encrypt_file(self.test_file, "secret123")
        enc_file = self.test_file + ".daeyang"

        # Try decrypting with wrong password
        with self.assertRaises(ValueError) as context:
            file_locker.decrypt_file(enc_file, "wrong_pass")
        self.assertEqual(str(context.exception), "비밀번호가 올바르지 않습니다.")

    def test_manual_rename_detected(self):
        # Create a normal file and manually rename it to .daeyang
        manual_file = "manual_renamed.daeyang"
        with open(manual_file, 'wb') as f:
            f.write(b"Normal unencrypted file content which has been manually renamed to .daeyang")

        try:
            with self.assertRaises(ValueError) as context:
                file_locker.decrypt_file(manual_file, "Daeyang")
            self.assertEqual(str(context.exception), "사용자가 수정한 파일입니다.")
        finally:
            if os.path.exists(manual_file):
                os.remove(manual_file)

if __name__ == '__main__':
    unittest.main()
