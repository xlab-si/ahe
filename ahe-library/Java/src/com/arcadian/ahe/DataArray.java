package com.arcadian.ahe;

import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;
import java.util.Arrays;
import java.util.List;

/**
 * This class represents a list of strings as passed by C functions.
 *
 * @author  Benjamin Benčina Tilen Marc
 * @version 0.0.1
 */
public class DataArray extends Structure {
    /**
     * A pointer (char **) to the first string in the list.
     */
    public PointerByReference data;
    /**
     * The length of the string list.
     */
    public int length;

    /**
     * Default constructor.
     */
    public DataArray() {
        super();
    }

    /**
     * Determines the order of the fields in this <code>struct</code>.
     *
     * @return  a list of string field names
     */
    protected List<String> getFieldOrder() {
        return Arrays.asList((new String[]{"data", "length"}));
    }

    /**
     * This constructor defines the string list as passed by C functions.
     *
     * @param   r0  a char ** pointer to the data
     * @param   r1  the length of the array
     */
    public DataArray(PointerByReference r0, int r1) {
        super();
        this.data = r0;
        this.length = r1;
    }

    /**
     * Returns a new ByReference implementation.
     *
     * @return  a new ByReference implementation.
     */
    protected DataArray.ByReference newByReference() {
        return new DataArray.ByReference();
    }

    /**
     * Returns a new ByValue implementation.
     *
     * @return  a new ByValue implementation.
     */
    protected DataArray.ByValue newByValue() {
        return new DataArray.ByValue();
    }

    /**
     * Determines that this class can be used "by value" w.r.t. the C programming language.
     */
    public static class ByValue extends DataArray implements  Structure.ByValue {
    }
 
    /**
     * Determines that this class can be used "by reference" w.r.t. the C programming language.
     */
    public static class ByReference extends DataArray implements  Structure.ByReference {
    }

}
