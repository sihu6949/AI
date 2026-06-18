import os
import unittest
import shutil
import file_locker

class TestFileLocker(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_data.txt"
        self.test_content = b"Hello, this is a secret document for Daeyang Locker testing."
        with open(self.test_file, 'wb') as f:
            f.write(self.test_content)

        # Temporary folder setup
        self.test_dir = "test_folder"
        os.makedirs(self.test_dir, exist_ok=True)
        with open(os.path.join(self.test_dir, "subfile1.txt"), 'w') as f:
            f.write("subfile1 content")
        os.makedirs(os.path.join(self.test_dir, "subdir"), exist_ok=True)
        with open(os.path.join(self.test_dir, "subdir", "subfile2.txt"), 'w') as f:
            f.write("subfile2 content")

    def tearDown(self):
        for f in [self.test_file, self.test_file + ".daeyang", "test_data.txt", self.test_dir + ".daeyang"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir)
            except OSError:
                pass

    def test_encrypt_decrypt_with_hint(self):
        # 1. Encrypt with custom password and hint
        hint_text = "my hint test"
        file_locker.encrypt_file(self.test_file, "secret123", hint_text)
        enc_file = self.test_file + ".daeyang"
        self.assertTrue(os.path.exists(enc_file))

        # 2. Check hint extraction
        extracted_hint = file_locker.get_file_hint(enc_file)
        self.assertEqual(extracted_hint, hint_text)

        # 3. Decrypt
        dec_file = file_locker.decrypt_file(enc_file, "secret123")
        self.assertEqual(dec_file, self.test_file)
        self.assertTrue(os.path.exists(self.test_file))

        with open(self.test_file, 'rb') as f:
            content = f.read()
        self.assertEqual(content, self.test_content)

    def test_folder_encrypt_decrypt(self):
        # 1. Encrypt folder
        file_locker.encrypt_file(self.test_dir, "folder_pass", "folder hint")
        enc_dir_file = self.test_dir + ".daeyang"
        self.assertTrue(os.path.exists(enc_dir_file))
        self.assertFalse(os.path.exists(self.test_dir))

        # 2. Decrypt folder using master password "Daeyang"
        dec_dir = file_locker.decrypt_file(enc_dir_file, "Daeyang")
        self.assertEqual(dec_dir, self.test_dir)
        self.assertTrue(os.path.exists(self.test_dir))
        self.assertFalse(os.path.exists(enc_dir_file))

        # 3. Verify directory contents
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "subfile1.txt")))
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "subdir", "subfile2.txt")))
        
        with open(os.path.join(self.test_dir, "subfile1.txt"), 'r') as f:
            self.assertEqual(f.read(), "subfile1 content")
            
        with open(os.path.join(self.test_dir, "subdir", "subfile2.txt"), 'r') as f:
            self.assertEqual(f.read(), "subfile2 content")

    def test_decrypt_wrong_password_fails(self):
        file_locker.encrypt_file(self.test_file, "secret123")
        enc_file = self.test_file + ".daeyang"

        with self.assertRaises(ValueError) as context:
            file_locker.decrypt_file(enc_file, "wrong_pass")
        self.assertEqual(str(context.exception), "비밀번호가 올바르지 않습니다.")

    def test_manual_rename_detected(self):
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
