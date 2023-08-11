package com.arcadian.ahe.exception;

/**
* This exception is thrown if the list of public keys passed to
* {@link com.arcadian.ahe.Ahe#Encrypt(Maabe, String, String, MaabePubKey[])} is empty.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyPublicKeyList extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyPublicKeyList(String errorMessage) {
        super(errorMessage);
    }
}



