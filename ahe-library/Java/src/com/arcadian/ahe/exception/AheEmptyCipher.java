package com.arcadian.ahe.exception;

/**
* This exception is thrown if an empty
* {@link com.arcadian.ahe.type.MaabeCipher} is passed to
* {@link com.arcadian.ahe.Ahe#Decrypt(Maabe, MaabeCipher, MaabeKey[])}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyCipher extends Exception {
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyCipher(String errorMessage) {
        super(errorMessage);
    }
}


