package com.arcadian.ahe.exception;

/**
* This exception is thrown if there is an error marshaling to JSON in
* {@link com.arcadian.ahe.Ahe#PubKeyToJSON(MaabePubKey)},
* {@link com.arcadian.ahe.Ahe#AttribKeysToJSON(MaabeKey[])}, or
* {@link com.arcadian.ahe.Ahe#CipherToJSON(MaabeCipher)}.
*
* @author  Benjamin Benčina Tilen Marc
* @version 0.0.1
*/
public class AheJSONMarshalError extends Exception { 
    /**
     * Currently just a default constructor.
     *
     * @param   errorMessage    the error message for this exception
     */
    public AheJSONMarshalError(String errorMessage) {
        super(errorMessage);
    }
}



