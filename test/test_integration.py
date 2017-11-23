'''End-to-end integration tests.'''
import os.path
import shutil
import subprocess
import sys
import tempfile
from textwrap import dedent
import unittest


DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')


class IntegrationBaseTestCase:
    '''Integration test base class that sets up a workspace.

    Base classes also need to inherit unittest.TestCase.'''
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def given_file_content(self, filename: str, content: str) -> str:
        '''Create a text file in the workspace with the given content.'''
        with open(self.path(filename), 'w') as f:
            f.write(content)

    def get_file_content(self, filename: str) -> str:
        '''Get the text content from a file in the workspace.'''
        with open(self.path(filename), 'r') as f:
            return f.read()

    def path(self, *parts) -> str:
        '''Append the given parts to the workspace path.'''
        return os.path.join(self.tmpdir.name, *parts)

    def run_certificate_builder(self, *args, **kwargs):
        '''Run ssl_certificate_builder main with the given arguments.'''
        full_args = [sys.executable, '-m', 'ssl_certificate_builder']
        full_args.extend(args)
        try:
            completed = subprocess.run(
                full_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                encoding=sys.stdin.encoding,
                **kwargs)
            completed.check_returncode()
        except (subprocess.TimeoutExpired,
                subprocess.CalledProcessError) as exc:
            print('STDOUT:', exc.stdout)
            print('STDERR:', exc.stderr)
            raise


class IntegrationTest(IntegrationBaseTestCase, unittest.TestCase):
    '''Integration tests.'''
    def test_should_create_self_signed_certificate(self):
        self.given_file_content('self-signed-cert.yaml', dedent('''\
            ---
            - basename: self-signed-cert
              C: DE
              O: gen-ssl
              CN: test-cert
            '''))

        self.run_certificate_builder(self.path('self-signed-cert.yaml'))

        cnf = self.get_file_content('self-signed-cert.cnf')
        self.assertIn('C=DE', cnf)
        self.assertIn('O=gen-ssl', cnf)
        self.assertIn('CN=test-cert', cnf)
        self.assertIn('basicConstraints=CA:false', cnf)
        self.assertIn(
            'keyUsage=digitalSignature, nonRepudiation, keyEncipherment',
            cnf)
        cert = self.get_file_content('self-signed-cert.cert')
        self.assertRegex(cert, '^-----BEGIN CERTIFICATE-----\n'
                               '(.+\n)+'
                               '-----END CERTIFICATE-----\n')
        key = self.get_file_content('self-signed-cert.key')
        self.assertRegex(key, '-----BEGIN RSA PRIVATE KEY-----\n'
                              '(.+\n)+'
                              '-----END RSA PRIVATE KEY-----\n')
        self.assertNotIn('Proc-Type', key)

    def test_should_create_ca_certificate(self):
        self.given_file_content('ca-cert.yaml', dedent('''\
            ---
            - basename: ca-cert
              type: ca
              C: DE
              O: gen-ssl
              CN: test-ca-cert
            '''))

        self.run_certificate_builder(self.path('ca-cert.yaml'))

        cnf = self.get_file_content('ca-cert.cnf')
        self.assertIn('C=DE', cnf)
        self.assertIn('O=gen-ssl', cnf)
        self.assertIn('CN=test-ca-cert', cnf)
        self.assertIn('basicConstraints=CA:true', cnf)
        self.assertIn('subjectKeyIdentifier=hash', cnf)
        self.assertIn('authorityKeyIdentifier=keyid:always, issuer', cnf)
        cert = self.get_file_content('ca-cert.cert')
        self.assertRegex(cert, '^-----BEGIN CERTIFICATE-----\n'
                               '(.+\n)+'
                               '-----END CERTIFICATE-----\n')
        key = self.get_file_content('ca-cert.key')
        self.assertRegex(key, '-----BEGIN RSA PRIVATE KEY-----\n'
                              '(.+\n)+'
                              '-----END RSA PRIVATE KEY-----\n')
        self.assertNotIn('Proc-Type', key)

    def test_should_use_basename_regardless_of_input_filename(self):
        self.given_file_content('cert-desc-filename.yaml', dedent('''\
            ---
            - basename: basename
              C: DE
              O: gen-ssl
              CN: test-cert
            '''))

        self.run_certificate_builder(self.path('cert-desc-filename.yaml'))

        result_files = os.listdir(self.path())
        result_files.sort()
        self.assertEqual(
            result_files,
            [
                'basename.cert', 'basename.cnf', 'basename.key',
                'cert-desc-filename.yaml'])

    def test_should_set_all_certificate_attributes(self):
        self.given_file_content('self-signed-cert.yaml', dedent('''\
            ---
            - basename: self-signed-cert
              C: DE
              ST: state
              L: location
              O: org
              OU: org-unit
              CN: common-name
            '''))

        self.run_certificate_builder(self.path('self-signed-cert.yaml'))

        cnf = self.get_file_content('self-signed-cert.cnf')
        self.assertIn('C=DE', cnf)
        self.assertIn('ST=state', cnf)
        self.assertIn('L=location', cnf)
        self.assertIn('O=org', cnf)
        self.assertIn('OU=org-unit', cnf)
        self.assertIn('CN=common-name', cnf)

    def test_should_use_key_size_4096(self):
        self.given_file_content('self-signed-cert.yaml', dedent('''\
            ---
            - basename: self-signed-cert
              CN: test
              key_size: 4096
            '''))

        self.run_certificate_builder(self.path('self-signed-cert.yaml'))

        cnf = self.get_file_content('self-signed-cert.key')
        self.assertGreater(len(cnf), 3000)

    def test_should_use_key_size_1024(self):
        self.given_file_content('self-signed-cert.yaml', dedent('''\
            ---
            - basename: self-signed-cert
              CN: test
              key_size: 1024
            '''))

        self.run_certificate_builder(self.path('self-signed-cert.yaml'))

        cnf = self.get_file_content('self-signed-cert.key')
        self.assertLess(len(cnf), 1000)

    def test_should_set_subject_alt_names(self):
        self.given_file_content('self-signed-cert.yaml', dedent('''\
            ---
            - basename: self-signed-cert
              CN: common-name
              subject_alt_names:
                - common-name
                - alt-1
                - alt-2
                - alt-3
            '''))

        self.run_certificate_builder(self.path('self-signed-cert.yaml'))

        cnf = self.get_file_content('self-signed-cert.cnf')
        self.assertIn('DNS.1=common-name', cnf)
        self.assertIn('DNS.2=alt-1', cnf)
        self.assertIn('DNS.3=alt-2', cnf)
        self.assertIn('DNS.4=alt-3', cnf)

    def test_should_create_password_protected_key(self):
        self.given_file_content('self-signed-cert.yaml', dedent('''\
            ---
            - basename: self-signed-cert
              C: DE
              O: gen-ssl
              CN: test-cert
              use_password: true
            '''))

        self.run_certificate_builder(
            self.path('self-signed-cert.yaml'),
            input='key-password\n', universal_newlines=True)

        key = self.get_file_content('self-signed-cert.key')
        self.assertRegex(key, '-----BEGIN RSA PRIVATE KEY-----\n'
                              'Proc-Type: 4,ENCRYPTED\n'
                              'DEK-Info: AES-256-CBC,[0-9a-fA-F]+\n'
                              '\n'
                              '(.+\n)+'
                              '-----END RSA PRIVATE KEY-----\n')

    def test_should_create_ca_signed_certificate(self):
        self.given_file_content('cert.yaml', dedent('''\
            ---
            - basename: cert
              C: DE
              O: gen-ssl
              CN: test-cert
              ca: ca
            '''))
        shutil.copy(os.path.join(DATA_DIR, 'ca.cert'), self.path())
        shutil.copy(os.path.join(DATA_DIR, 'ca.key'), self.path())

        self.run_certificate_builder(self.path('cert.yaml'))

        cnf = self.get_file_content('cert.cnf')
        self.assertIn('C=DE', cnf)
        self.assertIn('O=gen-ssl', cnf)
        self.assertIn('CN=test-cert', cnf)
        self.assertIn('basicConstraints=CA:false', cnf)
        self.assertIn(
            'keyUsage=digitalSignature, nonRepudiation, keyEncipherment',
            cnf)
        cert = self.get_file_content('cert.cert')
        self.assertRegex(cert, '^-----BEGIN CERTIFICATE-----\n'
                               '(.+\n)+'
                               '-----END CERTIFICATE-----\n')
        key = self.get_file_content('cert.key')
        self.assertRegex(key, '-----BEGIN RSA PRIVATE KEY-----\n'
                              '(.+\n)+'
                              '-----END RSA PRIVATE KEY-----\n')


if __name__ == '__main__':
    unittest.main()
