package com.arcadian.ahe.exception;

/**
* This exception is thrown if there is an error unmarshaling from JSON in
* {@link com.arcadian.ahe.Ahe#PubKeyFromJSON(String)},
* {@link com.arcadian.ahe.Ahe#AttribKeysFromJSON(String)}, or
* {@link com.arcadian.ahe.Ahe#CipherFromJSON(String)}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheJSONUnmarshalError extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheJSONUnmarshalError(String errorMessage) {
        super(errorMessage);
    }
}




