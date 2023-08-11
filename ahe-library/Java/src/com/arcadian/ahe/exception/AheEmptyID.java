package com.arcadian.ahe.exception;

/**
* This exception is thrown if an empty identifier string is passed to
* {@link com.arcadian.ahe.Ahe#NewMaabeAuth(Maabe, String, String[])}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyID extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyID(String errorMessage) {
        super(errorMessage);
    }
}


