package com.arcadian.ahe.exception;

/**
* This exception is thrown if the list of attributes passed to
* {@link com.arcadian.ahe.Ahe#NewMaabeAuth(Maabe, String, String[])} or
* {@link com.arcadian.ahe.Ahe#GenAttribKeys(MaabeAuth, String, String[])} is empty.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheEmptyAttributeList extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheEmptyAttributeList(String errorMessage) {
        super(errorMessage);
    }
}


