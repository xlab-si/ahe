package com.arcadian.ahe.exception;

/**
* This exception is thrown when if the list of attributes passed to the
* {@link com.arcadian.ahe.Ahe#NewMaabeAuth(Maabe, String, String[])} or
* {@link com.arcadian.ahe.Ahe#GenAttribKeys(MaabeAuth, String, String[])} functions contains an
* empty element.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyAttribute extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyAttribute(String errorMessage) {
        super(errorMessage);
    }
}

