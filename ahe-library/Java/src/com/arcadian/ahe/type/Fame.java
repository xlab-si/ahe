package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents the global information of the Fame scheme.
 *
 */
public class Fame {
    /**
     * A string prime order of the underlying curve.
     */
    public String fame = "";

    /**
     * Default constructor creates an empty object.
     */
    public Fame() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   maabeStrList    the string array of serialized parameters
     */
    public Fame(String fameStr) {
        this.fame = fameStr;
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

        return this.fame;
    }

    /**
     * Determines whether the object is considered 'empty'.
     *
     * @return  <code>true</code> if any of the object properties are empty;
     *          <code>false</code> otherwise
     */
    public boolean isEmpty() {
        return fame.equals("");
    }
}
