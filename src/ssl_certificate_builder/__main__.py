#!/usr/bin/env python3

import getpass
import itertools
import os
import subprocess
import sys
import textwrap

from jinja2 import Template
import yaml


class CertificateInfo:
    DEFAULT_KEY_SIZE = 2048
    DEFAULT_EXPIRATION_DAYS = 10000

    CERTIFICATE_EXT = "cert"
    PRIVATE_KEY_EXT = "key"
    CERT_REQUEST_EXT = "csr"
    CONFIG_EXT = "cnf"

    CONFIG_FILE_TEMPLATE = Template(textwrap.dedent("""\
        extensions=v3_extensions

        [req]
        req_extensions=v3_extensions
        x509_extensions=v3_extensions
        distinguished_name=req_distinguished_name
        prompt=no

        [req_distinguished_name]
        {% if cert_info.C %}C={{ cert_info.C }}{% endif %}
        {% if cert_info.ST %}ST={{ cert_info.ST }}{% endif %}
        {% if cert_info.L %}L={{ cert_info.L }}{% endif %}
        {% if cert_info.O %}O={{ cert_info.O }}{% endif %}
        {% if cert_info.OU %}OU={{ cert_info.OU }}{% endif %}
        {% if cert_info.CN %}CN={{ cert_info.CN }}{% endif %}

        [v3_extensions]
        {% if cert_info.is_ca -%}
        basicConstraints=CA:true
        subjectKeyIdentifier=hash
        authorityKeyIdentifier=keyid:always, issuer
        {%- else -%}
        basicConstraints=CA:false
        keyUsage=digitalSignature, nonRepudiation, keyEncipherment
        {%- endif %}
        {% if cert_info.subject_alt_names -%}
        subjectAltName=@alt_names

        [alt_names]
        {% for alt_name in cert_info.subject_alt_names -%}
        DNS.{{ loop.index }}={{ alt_name }}
        {% endfor %}
        {%- endif %}
    """))

    def __init__(self, basename,
                 C="", ST="", L="", O="", OU="", CN="",
                 subject_alt_names=None, is_ca=False,
                 ca=None,
                 key_size=DEFAULT_KEY_SIZE,
                 expiration_days=DEFAULT_EXPIRATION_DAYS,
                 use_password=False):
        self.basename = basename

        self.C = C
        self.ST = ST
        self.L = L
        self.O = O
        self.OU = OU
        self.CN = CN

        self.subject_alt_names = subject_alt_names
        self.is_ca = is_ca
        self.ca = ca
        self.key_size = key_size
        self.expiration_days = expiration_days
        self.use_password = use_password

    def get_config_file(self):
        return self.CONFIG_FILE_TEMPLATE.render(cert_info=self)

    @property
    def certificate_name(self):
        return self._filename(self.CERTIFICATE_EXT)

    @property
    def private_key_name(self):
        return self._filename(self.PRIVATE_KEY_EXT)

    @property
    def certificate_request_name(self):
        return self._filename(self.CERT_REQUEST_EXT)

    @property
    def config_file_name(self):
        return self._filename(self.CONFIG_EXT)

    def _filename(self, ext):
        return "%s.%s" % (self.basename, ext)

    @classmethod
    def from_dict(cls, dict):
        kwargs = {'is_ca': False}
        for key, value in dict.items():
            if key == 'type':
                kwargs['is_ca'] = value == 'ca'
            else:
                kwargs[key.replace('-', '_')] = value
        return cls(**kwargs)


class OpenSSL:
    DEFAULT_OPENSSL = "openssl"

    def __init__(self, openssl=DEFAULT_OPENSSL):
        self.openssl = openssl

    def __call__(self, pos_args, *opts, **opts_with_values):
        args = self.build_openssl_commandline(pos_args, *opts,
                                              **opts_with_values)
        subprocess.check_call(args)

    def build_openssl_commandline(self, pos_args, *opts, **opts_with_values):
        args = [self.openssl]
        if len(pos_args):
            args.append(pos_args[0])
            pos_args = pos_args[1:]

        args.extend("-%s" % opt for opt in opts)
        args.extend(itertools.chain.from_iterable(
            ("-%s" % opt, value)
            for opt, value
            in opts_with_values.items()))
        args.extend(pos_args)

        return list(map(str, args))


class CertificateBuilder:
    def __init__(self, cert_info, base_dir=None, openssl=OpenSSL()):
        self.cert_info = cert_info
        self.base_dir = base_dir if base_dir else os.curdir
        self.openssl = openssl
        self.key_password = None

    def generate_config_file(self):
        with open(self._path(self.cert_info.config_file_name), "w") as f:
            f.write(self.cert_info.get_config_file())

    def generate_private_key(self):
        args = [["genrsa", self.cert_info.key_size]]
        if self.cert_info.use_password:
            args.append('aes256')
        self.openssl(
            *args,
            out=self._path(self.cert_info.private_key_name),
            passout='pass:%s' % self.key_password)

    def generate_certificate_request(self):
        self.openssl(
            ["req"], "new", "sha512",
            out=self._path(self.cert_info.certificate_request_name),
            key=self._path(self.cert_info.private_key_name),
            config=self._path(self.cert_info.config_file_name),
            passin='pass:%s' % self.key_password)

    def generate_self_signed_certificate(self):
        self.openssl(
            ["req"], "x509", "new", "sha512", "nodes",
            key=self._path(self.cert_info.private_key_name),
            out=self._path(self.cert_info.certificate_name),
            days=self.cert_info.expiration_days,
            config=self._path(self.cert_info.config_file_name),
            passin='pass:%s' % self.key_password)

    def generate_ca_signed_certificate(self):
        self.openssl(
            ["x509"], "req", "CAcreateserial",
            CA=self._path("%s.%s"
                          % (self.cert_info.ca,
                             CertificateInfo.CERTIFICATE_EXT)),
            CAkey=self._path("%s.%s"
                             % (self.cert_info.ca,
                                CertificateInfo.PRIVATE_KEY_EXT)),
            out=self._path(self.cert_info.certificate_name),
            extfile=self._path(self.cert_info.config_file_name),
            days=self.cert_info.expiration_days,
            **{"in": self._path(self.cert_info.certificate_request_name)})

    def generate_full_certificate(self):
        if self.cert_info.use_password:
            if sys.stdin.isatty():
                self.key_password = getpass.getpass()
            else:
                print('Password:', end=' ')
                self.key_password = input()
        self.generate_config_file()
        self.generate_private_key()
        if self.cert_info.ca is None:
            self.generate_self_signed_certificate()
        else:
            self.generate_certificate_request()
            self.generate_ca_signed_certificate()

    def _path(self, filename):
        return os.path.join(self.base_dir, filename)


def get_cert_infos(filenames):
    for filename in filenames:
        with open(filename, 'r') as f:
            document = yaml.load(f)
        basedir = os.path.dirname(filename)
        for item in document:
            yield basedir, CertificateInfo.from_dict(item)


def generate_certificates(cert_infos):
    for basedir, cert_info in cert_infos:
        builder = CertificateBuilder(cert_info, base_dir=basedir)
        builder.generate_full_certificate()


def main():
    cert_infos = get_cert_infos(sys.argv[1:])
    generate_certificates(cert_infos)


if __name__ == "__main__":
    main()
