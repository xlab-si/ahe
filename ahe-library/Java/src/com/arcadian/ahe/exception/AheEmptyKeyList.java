package com.arcadian.ahe.exception;

/**
* This exception is thrown if the list of decryption keys passed to
* {@link com.arcadian.ahe.Ahe#Decrypt(Maabe, MaabeCipher, MaabeKey[])} is empty.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyKeyList extends Exception {
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyKeyList(String errorMessage) {
        super(errorMessage);
    }
}


