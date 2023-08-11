package com.arcadian.ahe;
import com.sun.jna.Structure;
import com.sun.jna.Pointer;
import java.util.List;
import java.util.Arrays;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

public class TwoValue extends Structure {
    public Pointer r0;
    public Pointer r1;

    public TwoValue() {
        super();
    }

    public TwoValue(Pointer r0, Pointer r1) {
        super();
        this.r0 = r0;
        this.r1 = r1;
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList((new String[]{"r0", "r1"}));
    }

    /**
     * Returns a new ByReference implementation.
     *
     * @return  a new ByReference implementation.
     */
    protected TwoValue.ByReference newByReference() {
        return new TwoValue.ByReference();
    }

    /**
     * Returns a new ByValue implementation.
     *
     * @return  a new ByValue implementation.
     */
    protected TwoValue.ByValue newByValue() {
        return new TwoValue.ByValue();
    }

    /**
     * Determines that this class can be used "by value" w.r.t. the C programming language.
     */
    public static class ByValue extends TwoValue implements  Structure.ByValue {
    }

    /**
     * Determines that this class can be used "by reference" w.r.t. the C programming language.
     */
    public static class ByReference extends TwoValue implements  Structure.ByReference {
    }
}

