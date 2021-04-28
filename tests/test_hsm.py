"""Unit tests for HSM utilities."""

from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

import pkcs11

import autocsr.protos.csr_pb2 as proto
from autocsr.hsm import DSA, Hsm, HsmFactory, SoftHsm

KeyType = proto.CertificateSigningRequest.KeyType
HashType = proto.CertificateSigningRequest.HashType
HsmInfo = proto.CertificateSigningRequest.HsmInfo


class TestSoftHsm(TestCase):
    """Test general HSM usage."""

    def setUp(self):
        """Set up a SoftHsm example."""
        with patch.object(SoftHsm, "__post_init__"):
            self.softhsm = SoftHsm(
                hash_type=HashType.SHA256,
                key_type=KeyType.RSA,
                token_label="test_token_label",
                key_label="test_key_label",
                user_pin="test_user_pin",
                so_file="test_so_file",
            )
        self.softhsm.pkcs11_key_type = Mock()
        self.softhsm.pkcs11_hash_type = Mock()

        self.mock_token = Mock()
        self.mock_open = MagicMock()
        self.mock_token.open.return_value = self.mock_open
        self.mock_session = self.mock_open.__enter__.return_value
        self.softhsm.token = self.mock_token

    @patch.object(Hsm, "pkcs11_to_crypto_key")
    def test_public_key(self, mock_pkcs11_to_crypto_key):
        """Test retrieving a public key from SoftHSM."""
        self.softhsm.public_key

        self.mock_token.open.assert_called_once_with(user_pin=self.softhsm.user_pin)
        self.mock_session.get_key.assert_called_once_with(
            label=self.softhsm.key_label,
            key_type=self.softhsm.pkcs11_key_type,
            object_class=pkcs11.ObjectClass.PUBLIC_KEY,
        )
        mock_pkcs11_to_crypto_key.assert_called_once_with(
            self.mock_session.get_key(
                label=self.softhsm.key_label,
                key_type=self.softhsm.pkcs11_key_type,
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
            )
        )

    def signing_helper(self, key_type: KeyType, mock_hash=None):
        """Test signing a message from SoftHSM."""
        test_message = b"test message"
        mock_key = Mock()
        self.mock_session.get_key.return_value = mock_key

        self.softhsm.key_type = key_type
        self.softhsm.sign(test_message)

        self.mock_token.open.assert_called_once_with(
            rw=True, user_pin=self.softhsm.user_pin
        )
        self.mock_session.get_key.assert_called_once_with(
            label=self.softhsm.key_label,
            key_type=self.softhsm.pkcs11_key_type,
            object_class=pkcs11.ObjectClass.PRIVATE_KEY,
        )

        if key_type == KeyType.EC:
            mock_key.sign.assert_called_once_with(
                mock_hash(self.softhsm.pkcs11_hash_type()).finalize(),
                mechanism=pkcs11.Mechanism.ECDSA,
            )
        else:
            mock_key.sign.assert_called_once_with(
                test_message, mechanism=self.softhsm.pkcs11_hash_type
            )

    def test_rsa_signing(self):
        """Test signing for RSA Keys."""
        self.signing_helper(KeyType.RSA)

    @patch("autocsr.hsm.encode_dsa_signature")
    def test_dsa_signing(self, mock_encode_dsa):
        """Test signing for DSA Keys."""
        self.signing_helper(KeyType.DSA)
        mock_encode_dsa.assert_called_once()

    @patch("autocsr.hsm.hashes.Hash")
    @patch("autocsr.hsm.encode_ecdsa_signature")
    def test_ec_signing(self, mock_encode_ecdsa, mock_hash):
        """Test signing for EC Keys."""
        self.signing_helper(KeyType.EC, mock_hash)
        mock_encode_ecdsa.assert_called_once()
        mock_hash.assert_called()

    def test_from_proto(self):
        """Test the creation of SoftHsm from a protobuf."""
        softhsm = proto.CertificateSigningRequest.SoftHsm()
        softhsm.token_label = "token_label"
        softhsm.key_label = "key_label"
        softhsm.user_pin = "user_pin"
        softhsm.so_file = "so_file"

        hsm_info = HsmInfo()
        hsm_info.softhsm.CopyFrom(softhsm)
        hsm_info.key_type = KeyType.RSA

        hash_type = HashType.SHA256

        with patch.object(SoftHsm, "__post_init__"):
            self.assertIsInstance(
                SoftHsm.from_proto(hsm_info, hash_type),
                SoftHsm,
                "Should be able to create SoftHsm from protobuf",
            )

    @patch("autocsr.hsm.load_der_public_key")
    @patch("autocsr.hsm.encode_ec_public_key")
    @patch.object(DSA, "construct")
    @patch("autocsr.hsm.encode_rsa_public_key")
    def test_pkcs11_to_crypto_key(
        self,
        mock_encode_rsa,
        mock_construct_dsa,
        mock_encode_ec,
        mock_load_pubkey,
    ):
        """Test conversion of pkcs11 key to crypto key."""
        self.softhsm.pkcs11_key_type = pkcs11.KeyType.RSA
        self.softhsm.pkcs11_to_crypto_key(MagicMock())
        mock_encode_rsa.assert_called_once()
        mock_construct_dsa.assert_not_called()
        mock_encode_ec.assert_not_called()
        mock_load_pubkey.assert_called_once()

        self.softhsm.pkcs11_key_type = pkcs11.KeyType.DSA
        self.softhsm.pkcs11_to_crypto_key(MagicMock())
        mock_encode_rsa.assert_called_once()
        mock_construct_dsa.assert_called_once()
        mock_encode_ec.assert_not_called()
        self.assertEqual(
            mock_load_pubkey.call_count,
            2,
            "Public key loading should be called twice",
        )

        self.softhsm.pkcs11_key_type = pkcs11.KeyType.EC
        self.softhsm.pkcs11_to_crypto_key(MagicMock())
        mock_encode_rsa.assert_called_once()
        mock_construct_dsa.assert_called_once()
        mock_encode_ec.assert_called_once()
        self.assertEqual(
            mock_load_pubkey.call_count,
            3,
            "Public key loading should be called twice",
        )

    class TestHsmFactory(TestCase):
        """Test HsmFactory's HSM creation."""

        def test_from_hsm_info(self):
            """Test creating HSM from HsmInfo."""
            softhsm = proto.CertificateSigningRequest.SoftHsm()
            softhsm.token_label = "token_label"
            softhsm.key_label = "key_label"
            softhsm.user_pin = "user_pin"
            softhsm.so_file = "so_file"

            hsm_info = HsmInfo()
            hsm_info.softhsm.CopyFrom(softhsm)
            hsm_info.key_type = KeyType.RSA

            hash_type = HashType.SHA256

            with patch.object(SoftHsm, "__post_init__"):
                self.assertIsInstance(
                    HsmFactory.from_hsm_info(hsm_info, hash_type), SoftHsm
                )
