package com.arcadian.ahe.exception;

/**
* This exception is thrown if an empty global identifier string is passed to
* {@link com.arcadian.ahe.Ahe#GenAttribKeys(MaabeAuth, String, String[])}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyGid extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyGid(String errorMessage) {
        super(errorMessage);
    }
}

