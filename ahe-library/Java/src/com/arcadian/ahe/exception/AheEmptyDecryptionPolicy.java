package com.arcadian.ahe.exception;

/**
* This exception is thrown if an empty boolean formula is passed to
* {@link com.arcadian.ahe.Ahe#Encrypt(Maabe, String, String, MaabePubKey[])}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyDecryptionPolicy extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyDecryptionPolicy(String errorMessage) {
        super(errorMessage);
    }
}

