package com.arcadian.ahe.test;

import junit.framework.TestCase;
import static org.junit.Assert.assertThrows;

import com.arcadian.ahe.type.MaabeAuth;
import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

public class TestMaabeAuth extends TestCase {
    public void testIsEmpty() {
        MaabeAuth a1 = new MaabeAuth();
        assertTrue(a1.isEmpty());
        String[] bad = new String[]{"1", "2", "3"};
        MaabeAuth a2 = new MaabeAuth(bad);
        assertTrue(a2.isEmpty());
        String[] good = new String[]{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};
        MaabeAuth a3 = new MaabeAuth(good);
        assertFalse(a3.isEmpty());
    }

    public void testToStringList() {
        MaabeAuth a1 = new MaabeAuth();
        AheOperationOnEmptyObject err = assertThrows(AheOperationOnEmptyObject.class, () -> a1.toStringList());
        assertEquals(err.getMessage(), "");
    }
}
