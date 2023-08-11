package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents a public keys in the Fame scheme.
 *
 */
public class FamePubKey {
    /**
     * A string representation of the public key.
     */
    public String pubKey = "";

    /**
     * Default constructor creates an empty object.
     */
    public FamePubKey() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   seckeyStr   the string array of serialized parameters
     */
    public FamePubKey(String pubkeyStr) {
        pubKey = pubkeyStr;
    }

    /**
     * Transfers the object's properties back into a string array.
     *
     * @return  a string list representing this object
     * @throws  AheOperationOnEmptyObject   if the object is considered empty
     */
    public String toString() {

        return pubKey;
    }

    /**
     * Determines whether the object is considered 'empty'.
     *
     * @return  <code>true</code> if any of the object properties are empty;
     *          <code>false</code> otherwise
     */
    public boolean isEmpty() {
        return pubKey == "";
    }
}

