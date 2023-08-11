package com.arcadian.ahe.exception;

/**
* This exception is thrown if an empty message string is passed to
* {@link com.arcadian.ahe.Ahe#Encrypt(Maabe, String, String, MaabePubKey[])}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyMessage extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyMessage(String errorMessage) {
        super(errorMessage);
    }
}
