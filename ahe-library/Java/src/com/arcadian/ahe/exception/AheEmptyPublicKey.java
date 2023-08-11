package com.arcadian.ahe.exception;

/**
* This exception is thrown the list of public keys passed to
* {@link com.arcadian.ahe.Ahe#Encrypt(Maabe, String, String, MaabePubKey[])}
* contains an emptyelement.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyPublicKey extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyPublicKey(String errorMessage) {
        super(errorMessage);
    }
}


