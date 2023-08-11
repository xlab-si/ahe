class AheEmptyMessage(Exception):
    """This exception is raised if an empty message string is passed to the
    Encrypt function.
    """
    pass


class AheEmptyDecryptionPolicy(Exception):
    """This exception is raised if an empty boolean formula string is passed to
    the Encrypt function.
    """
    pass


class AheEmptyGid(Exception):
    """This exception is raised if an empty global identifier string is passed
    to the GenAttribKeys function.
    """
    pass


class AheEmptyAttribute(Exception):
    """This exception is raised if the list of attributes passed to the NewAuth
    or GenAttribKeys functions contains an empty element.
    """
    pass


class AheEmptyAttributeList(Exception):
    """This exception is raised if the list of attributes passed to the NewAuth
    or GenAttribKeys functions is empty.
    """
    pass


class AheEmptyPublicKey(Exception):
    """This exception is raised if the list of public keys passed to the
    Encrypt functions contains an empty element.
    """
    pass


class AheEmptyPublicKeyList(Exception):
    """This exception is raised if the list of public keys passed to the
    Encrypt functions is empty.
    """
    pass


class AheEmptyID(Exception):
    """This exception is raised if an empty identifier string is passed to the
    NewAuth function.
    """
    pass


class AheEmptyScheme(Exception):
    """This exception is raised if an empty Scheme object is passed.
    """
    pass


class AheEmptyMaabeAuth(Exception):
    """This exception is raised if an empty MaabeAuth object is passed to the
    GenAttribKeys function.
    """
    pass


class AheEmptyCipher(Exception):
    """This exception is raised if an empty MaabeCipher object is passed to the
    Decrypt function.
    """
    pass


class AheEmptyKey(Exception):
    """This exception is raised if the list of decryption keys passed to the
    Decrypt function contains an empty element.
    """
    pass


class AheEmptyKeyList(Exception):
    """This exception is raised if the list of decryption keys passed to the
    Decrypt function is empty.
    """
    pass


class AheTypeConversionError(Exception):
    """This exception is raised if there is an error converting C types to
    Python types.
    """
    pass


class AheOperationOnEmptyObject(Exception):
    """This exception is raised if a class method is operating on an 'empty'
    object.
    """
    pass

class AheVerificationError(Exception):
    """This exception is raised if verification fails.
    """
    pass

class AheSchemeError(Exception):
    """This exception is raised if verification fails.
    """
    pass
