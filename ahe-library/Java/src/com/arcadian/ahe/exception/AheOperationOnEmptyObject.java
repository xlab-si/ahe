package com.arcadian.ahe.exception;

/**
* This exception is thrown if a class method is operating on an 'empty' object.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheOperationOnEmptyObject extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheOperationOnEmptyObject(String errorMessage) {
        super(errorMessage);
    }
}


