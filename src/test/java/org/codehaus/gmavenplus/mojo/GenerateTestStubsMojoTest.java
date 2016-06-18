/*
 * Copyright 2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.codehaus.gmavenplus.mojo;

import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.codehaus.gmavenplus.model.Version;
import org.codehaus.gmavenplus.util.ClassWrangler;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.util.HashSet;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anySet;
import static org.mockito.Mockito.*;


/**
 * @author Keegan Witt
 */
public class GenerateTestStubsMojoTest {
    private static final String INTENTIONAL_EXCEPTION_MESSAGE = "Intentionally blowing up.";

    @Spy
    private GenerateTestStubsMojo generateTestStubsMojo;

    @Before
    public void setup() throws Exception {
        MockitoAnnotations.initMocks(this);
        doReturn(new HashSet<File>()).when(generateTestStubsMojo).getTestSources();
        doReturn(new HashSet<File>()).when(generateTestStubsMojo).getTestStubs();
        generateTestStubsMojo.project = mock(MavenProject.class);
        generateTestStubsMojo.testStubsOutputDirectory = mock(File.class);
        doReturn(mock(Build.class)).when(generateTestStubsMojo.project).getBuild();
        generateTestStubsMojo.classWrangler = mock(ClassWrangler.class);
        doReturn(new Version(1, 8, 2)).when(generateTestStubsMojo.classWrangler).getGroovyVersion();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testCallsExpectedMethods() throws Exception {
        doReturn(true).when(generateTestStubsMojo).groovyVersionSupportsAction(any(ClassWrangler.class));
        doNothing().when(generateTestStubsMojo).doStubGeneration(anySet(), any(File.class));
        generateTestStubsMojo.execute();
        verify(generateTestStubsMojo, times(1)).doStubGeneration(anySet(), any(File.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testSkipped() throws Exception {
        doReturn(true).when(generateTestStubsMojo).groovyVersionSupportsAction(any(ClassWrangler.class));
        generateTestStubsMojo.skipTests = true;
        generateTestStubsMojo.execute();
        verify(generateTestStubsMojo, never()).doStubGeneration(anySet(), any(File.class));
    }

    @Test (expected = MojoExecutionException.class)
    @SuppressWarnings("unchecked")
    public void testClassNotFoundExceptionThrowsMojoExecutionException() throws Exception {
        doReturn(true).when(generateTestStubsMojo).groovyVersionSupportsAction(any(ClassWrangler.class));
        doThrow(new ClassNotFoundException(INTENTIONAL_EXCEPTION_MESSAGE)).when(generateTestStubsMojo).doStubGeneration(anySet(), any(File.class));
        generateTestStubsMojo.execute();
    }

    @Test (expected = MojoExecutionException.class)
    @SuppressWarnings("unchecked")
    public void testInvocationTargetExceptionThrowsMojoExecutionException() throws Exception {
        doReturn(true).when(generateTestStubsMojo).groovyVersionSupportsAction(any(ClassWrangler.class));
        doThrow(new InvocationTargetException(mock(Exception.class), INTENTIONAL_EXCEPTION_MESSAGE)).when(generateTestStubsMojo).doStubGeneration(anySet(), any(File.class));
        generateTestStubsMojo.execute();
    }

    @Test (expected = MojoExecutionException.class)
    @SuppressWarnings("unchecked")
    public void testInstantiationExceptionThrowsMojoExecutionException() throws Exception {
        doReturn(true).when(generateTestStubsMojo).groovyVersionSupportsAction(any(ClassWrangler.class));
        doThrow(new InstantiationException(INTENTIONAL_EXCEPTION_MESSAGE)).when(generateTestStubsMojo).doStubGeneration(anySet(), any(File.class));
        generateTestStubsMojo.execute();
    }

    @Test (expected = MojoExecutionException.class)
    @SuppressWarnings("unchecked")
    public void testIllegalAccessExceptionThrowsMojoExecutionException() throws Exception {
        doReturn(true).when(generateTestStubsMojo).groovyVersionSupportsAction(any(ClassWrangler.class));
        doThrow(new IllegalAccessException(INTENTIONAL_EXCEPTION_MESSAGE)).when(generateTestStubsMojo).doStubGeneration(anySet(), any(File.class));
        generateTestStubsMojo.execute();
    }

    @Test (expected = MojoExecutionException.class)
    @SuppressWarnings("unchecked")
    public void testMalformedURLExceptionThrowsMojoExecutionException() throws Exception {
        doReturn(true).when(generateTestStubsMojo).groovyVersionSupportsAction(any(ClassWrangler.class));
        doThrow(new MalformedURLException(INTENTIONAL_EXCEPTION_MESSAGE)).when(generateTestStubsMojo).doStubGeneration(anySet(), any(File.class));
        generateTestStubsMojo.execute();
    }

    @Test
    public void testGroovyVersionSupportsActionTrue() {
        doReturn(Version.parseFromString("1.5.0")).when(generateTestStubsMojo.classWrangler).getGroovyVersion();
        assertTrue(generateTestStubsMojo.groovyVersionSupportsAction(generateTestStubsMojo.classWrangler));
    }

    @Test
    public void testGroovyVersionSupportsActionFalse() {
        doReturn(Version.parseFromString("1.0")).when(generateTestStubsMojo.classWrangler).getGroovyVersion();
        assertFalse(generateTestStubsMojo.groovyVersionSupportsAction(generateTestStubsMojo.classWrangler));
    }

}
