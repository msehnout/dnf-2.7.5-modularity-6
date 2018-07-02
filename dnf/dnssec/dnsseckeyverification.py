import base64
import hashlib
import logging
import re
import unbound

from enum import Enum
from dnf.dnssec import DnssecError
from dnf.i18n import _
import dnf.rpm.transaction


logger = logging.getLogger("dnf")

# TODO: make this feature optional

RR_TYPE_OPENPGPKEY = 61


def email2location(email_address, tag="_openpgpkey"):
    # type: (str, str) -> str
    """
    Implements RFC 7929, section 3
    https://tools.ietf.org/html/rfc7929#section-3
    :param email_address:
    :param tag:
    :return:
    """
    split = email_address.split("@")
    if len(split) == 2:
        local = split[0]
        domain = split[1]
        hash = hashlib.sha256()
        hash.update(local.encode('utf-8'))
        digest = base64.b16encode(hash.digest()[0:28])\
            .decode("utf-8")\
            .lower()
        return digest + "." + tag + "." + domain
    else:
        raise DnssecError


class Validity(Enum):
    """
    Output of the verification algorithm.
    TODO: this type might be simplified in order to less reflect the underlying DNS layer.
    TODO: more specifically the variants from 3 to 5 should have more understandable names
    """
    VALID = 1
    REVOKED = 2
    PROVEN_NONEXISTENCE = 3
    RESULT_NOT_SECURE = 4
    BOGUS_RESULT = 5
    ERROR = 9


class NoKey:
    """
    This class represents an absence of a key in the cache. It is an expression of non-existence using the Python's
    type system.
    """
    pass


class KeyInfo:
    """
    Wrapper class for email and associated verification key, where both are represented in form of a string.
    """
    def __init__(self, email=None, key=None):
        self.email = email
        self.key = key

    @staticmethod
    def from_rpm_key_object(userid, raw_key):
        # type: (str, bytes) -> KeyInfo
        """
        Since dnf uses different format of the key than the one used in DNS RR, I need to convert the
        former one into the new one.
        """
        input_email = re.search('<(.*@.*)>', userid)
        if input_email is None:
            raise DnssecError

        email = input_email.group(1)
        key = raw_key.decode('ascii').split('\n')

        start = 0
        stop = 0
        for i in range(0, len(key)):
            if key[i] == '-----BEGIN PGP PUBLIC KEY BLOCK-----':
                start = i
            if key[i] == '-----END PGP PUBLIC KEY BLOCK-----':
                stop = i

        cat_key = ''.join(key[start + 2:stop - 1]).encode('ascii')
        return KeyInfo(email, cat_key)


class DNSSECKeyVerification:
    """
    The main class when it comes to verification itself. It wraps Unbound context and a cache with
    already obtained results.
    """

    # Mapping from email address to b64 encoded public key or NoKey in case of proven nonexistence
    _cache = {}
    # type: Dict[str, Union[str, NoKey]]

    @staticmethod
    def _cache_hit(key_union, input_key_string):
        # type: (Union[str, NoKey], str) -> Validity
        """
        Compare the key in case it was found in the cache.
        """
        if key_union == input_key_string:
            return Validity.VALID
        elif key_union is NoKey:
            return Validity.PROVEN_NONEXISTENCE
        else:
            return Validity.REVOKED

    @staticmethod
    def _cache_miss(input_key):
        # type: (KeyInfo) -> Validity
        """
        In case the key was not found in the cache, create an Unbound context and contact the DNS system
        """
        ctx = unbound.ub_ctx()
        if ctx.set_option("verbosity:", "0") != 0:
            logger.debug("Unbound context: Failed to set verbosity")

        if ctx.set_option("qname-minimisation:", "yes") != 0:
            logger.debug("Unbound context: Failed to set qname minimisation")

        if ctx.resolvconf() != 0:
            logger.debug("Unbound context: Failed to read resolv.conf")

        if ctx.add_ta_file("/var/lib/unbound/root.key") != 0:
            logger.debug("Unbound context: Failed to add trust anchor file")

        status, result = ctx.resolve(email2location(input_key.email),
                                     RR_TYPE_OPENPGPKEY, unbound.RR_CLASS_IN)
        if status != 0:
            return Validity.ERROR
        if result.bogus:
            return Validity.BOGUS_RESULT
        if not result.secure:
            return Validity.RESULT_NOT_SECURE
        if result.nxdomain:
            return Validity.PROVEN_NONEXISTENCE
        if not result.havedata:
            # TODO: This is weird result, but there is no way to perform validation, so just return an error
            return Validity.ERROR
        else:
            data = result.data.as_raw_data()[0]
            dns_data_b64 = base64.b64encode(data)
            if dns_data_b64 == input_key.key:
                return Validity.VALID
            else:
                return Validity.REVOKED

    @staticmethod
    def verify(input_key):
        # type: (KeyInfo) -> Validity
        """
        Public API. Use this method to verify a KeyInfo object.
        """
        key_union = DNSSECKeyVerification._cache.get(input_key.email)
        if key_union is not None:
            return DNSSECKeyVerification._cache_hit(key_union, input_key.key)
        else:
            result = DNSSECKeyVerification._cache_miss(input_key)
            if result == Validity.VALID:
                DNSSECKeyVerification._cache[input_key.email] = input_key.key
            elif result == Validity.PROVEN_NONEXISTENCE:
                DNSSECKeyVerification._cache[input_key.email] = NoKey()
            return result


def nice_user_msg(ki, v):
    # type: (KeyInfo, Validity) -> str
    """
    Inform the user about key validity in a human readable way.
    """
    prefix = _("DNSSEC extension: Key for user ") + ki.email + " "
    if v == Validity.VALID:
        return prefix + _("is valid.")
    else:
        return prefix + _("has unknown status.")


def any_msg(m):
    # type: (str) -> str
    """
    Label any given message with DNSSEC extension tag
    """
    return _("DNSSEC extension: ") + m


class RpmImportedKeys:
    """
    Wrapper around keys, that are imported in the RPM database.

    The keys are stored in packages with name gpg-pubkey, where the version and
    release is different for each of them. The key content itself is stored as
    an ASCII armored string in the package description, so it needs to be parsed
    before it can be used.
    """
    @staticmethod
    def _query_db_for_gpg_keys():
        # type: () -> List[KeyInfo]
        # TODO: base.conf.installroot ?? -----------------------\
        transaction_set = dnf.rpm.transaction.TransactionWrapper()
        packages = transaction_set.dbMatch("name", "gpg-pubkey")
        return_list = []
        for pkg in packages:
            packager = pkg['packager'].decode('ascii')
            email = re.search('<(.*@.*)>', packager).group(1)
            description = pkg['description']
            key_lines = description.decode('ascii').split('\n')[3:-3]
            key_str = ''.join(key_lines)
            return_list += [KeyInfo(email, key_str.encode('ascii'))]

        return return_list

    @staticmethod
    def check_imported_keys_validity():
        keys = RpmImportedKeys._query_db_for_gpg_keys()
        logger.info(any_msg(_("Testing already imported keys for their validity.")))
        for key in keys:
            result = DNSSECKeyVerification.verify(key)
            # TODO: remove revoked keys automatically
            logger.info(any_msg("Key associated with identity " + key.email +
                        " was tested with result: " + str(result)))
