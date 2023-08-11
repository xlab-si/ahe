package com.arcadian.ahe.test;

import junit.framework.TestCase;
import static org.junit.Assert.assertThrows;

import com.arcadian.ahe.type.MaabeSecKey;
import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

public class TestMaabeSecKey extends TestCase {
    public void testIsEmpty() {
        MaabeSecKey m1 = new MaabeSecKey();
        assertTrue(m1.isEmpty());
        String[] bad = new String[]{"1", "2"};
        MaabeSecKey m2 = new MaabeSecKey(bad);
        assertTrue(m2.isEmpty());
        String[] good = new String[]{"1", "2", "3"};
        MaabeSecKey m3 = new MaabeSecKey(good);
        assertFalse(m3.isEmpty());
    }

    public void testToStringList() {
        MaabeSecKey m1 = new MaabeSecKey();
        AheOperationOnEmptyObject err = assertThrows(AheOperationOnEmptyObject.class, () -> m1.toStringList());
        assertEquals(err.getMessage(), "");
    }
}
