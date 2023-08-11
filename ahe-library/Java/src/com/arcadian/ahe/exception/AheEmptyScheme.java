package com.arcadian.ahe.exception;

/**
* This exception is thrown if an empty
* {@link com.arcadian.ahe.type.Maabe} is passed to
* {@link com.arcadian.ahe.Ahe#NewMaabeAuth(Maabe, String, String[])},
* {@link com.arcadian.ahe.Ahe#Encrypt(Maabe, String, String, MaabePubKey[])}, or
* {@link com.arcadian.ahe.Ahe#Decrypt(Maabe, MaabeCipher, MaabeKey[])}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyScheme extends Exception {
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyScheme(String errorMessage) {
        super(errorMessage);
    }
}


