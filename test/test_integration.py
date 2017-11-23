'''End-to-end integration tests.'''
import os.path
import subprocess
import sys
import tempfile
from textwrap import dedent
import unittest


class IntegrationBaseTestCase:
    '''Integration test base class that sets up a workspace.

    Base classes also need to inherit unittest.TestCase.'''
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def given_file_content(self, filename, content):
        '''Create a text file in the workspace with the given content.'''
        with open(self.path(filename), 'w') as f:
            f.write(content)

    def get_file_content(self, filename):
        '''Get the text content from a file in the workspace.'''
        with open(self.path(filename), 'r') as f:
            return f.read()

    def path(self, *parts):
        '''Append the given parts to the workspace path.'''
        return os.path.join(self.tmpdir.name, *parts)

    def run_certificate_builder(self, *args):
        '''Run ssl_certificate_builder main with the given arguments.'''
        full_args = [sys.executable, '-m', 'ssl_certificate_builder']
        full_args.extend(args)
        subprocess.check_call(full_args)


class IntegrationTest(IntegrationBaseTestCase, unittest.TestCase):
    '''Integration tests.'''
    def test_should_create_self_signed_certificate(self):
        self.given_file_content('self-signed-cert.yaml', dedent('''\
            ---
            - basename: self-signed-cert
              C: DE
              O: gen-ssl
              CN: tes-cert
            '''))

        self.run_certificate_builder(self.path('self-signed-cert.yaml'))

        # TODO: verify the output


if __name__ == '__main__':
    unittest.main()
