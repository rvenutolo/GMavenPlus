/*
 * Copyright (C) 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.codehaus.gmavenplus;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;


public class SomeClassTest {

    @Test
    public void testSomeMethod() {
        Method method = SomeClass.class.getDeclaredMethod("someMethod", String.class, String.class);
        List<String> parameterNames = Arrays.asList(method.getParameters());

        Assert.assertEquals(2, parameterNames.size());
        Assert.assertEquals("param1", parameterNames.get(0));
        Assert.assertEquals("param1", parameterNames.get(1));
    }

}
