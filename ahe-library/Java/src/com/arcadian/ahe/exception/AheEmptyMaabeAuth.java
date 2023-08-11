package com.arcadian.ahe.exception;

/**
* This exception is thrown if an empty
* {@link com.arcadian.ahe.type.MaabeAuth} is passed to
* {@link com.arcadian.ahe.Ahe#NewMaabeAuth(Maabe, String, String[])}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyMaabeAuth extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyMaabeAuth(String errorMessage) {
        super(errorMessage);
    }
}


