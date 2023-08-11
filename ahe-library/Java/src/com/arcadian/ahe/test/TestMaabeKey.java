package com.arcadian.ahe.test;

import junit.framework.TestCase;
import static org.junit.Assert.assertThrows;

import com.arcadian.ahe.type.MaabeKey;
import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

public class TestMaabeKey extends TestCase {
    public void testIsEmpty() {
        MaabeKey m1 = new MaabeKey();
        assertTrue(m1.isEmpty());
        String[] bad = new String[]{"1", "2"};
        MaabeKey m2 = new MaabeKey(bad);
        assertTrue(m2.isEmpty());
        String[] good = new String[]{"1", "2", "3"};
        MaabeKey m3 = new MaabeKey(good);
        assertFalse(m3.isEmpty());
    }

    public void testToStringList() {
        MaabeKey m1 = new MaabeKey();
        AheOperationOnEmptyObject err = assertThrows(AheOperationOnEmptyObject.class, () -> m1.toStringList());
        assertEquals(err.getMessage(), "");
    }
}
