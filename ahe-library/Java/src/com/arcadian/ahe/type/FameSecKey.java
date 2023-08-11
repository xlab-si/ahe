package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents a collection of secret keys in the Maabe scheme
 * belonging to a single authority.
 *
 */
public class FameSecKey {
    /**
     * A string list of attributes managed by this authority.
     */
    public String secKey = "";

    /**
     * Default constructor creates an empty object.
     */
    public FameSecKey() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   seckeyStr   the string array of serialized parameters
     */
    public FameSecKey(String seckeyStr) {
        secKey = seckeyStr;
    }

    /**
     * Transfers the object's properties back into a string array.
     *
     * @return  a string list representing this object
     * @throws  AheOperationOnEmptyObject   if the object is considered empty
     */
    public String toString() {
//     throws AheOperationOnEmptyObject {
//         if (this.isEmpty()) {
//             throw new AheOperationOnEmptyObject("");
//         }

        return secKey;
    }

    /**
     * Determines whether the object is considered 'empty'.
     *
     * @return  <code>true</code> if any of the object properties are empty;
     *          <code>false</code> otherwise
     */
    public boolean isEmpty() {
        return secKey == "";
    }
}

