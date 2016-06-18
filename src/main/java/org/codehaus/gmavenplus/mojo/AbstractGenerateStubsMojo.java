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

package org.codehaus.gmavenplus.mojo;

import org.codehaus.gmavenplus.groovyworkarounds.DotGroovyFile;
import org.codehaus.gmavenplus.model.Version;
import org.codehaus.gmavenplus.util.ClassWrangler;
import org.codehaus.gmavenplus.util.FileUtils;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * The base generate stubs mojo, which all generate stubs mojos extend.
 *
 * @author Keegan Witt
 * @since 1.0-beta-1
 */
public abstract class AbstractGenerateStubsMojo extends AbstractGroovyStubSourcesMojo {
    /*
     * TODO: support Groovy 1.5.0 - 1.8.1?
     * For some reason, the JavaStubCompilationUnit is silently not creating my
     * stubs (although it does create the target directory) when I use other
     * versions.
     */

    /**
     * Groovy 2.9.0 beta-1 version.
     */
    protected static final Version GROOVY_1_9_0_BETA1 = new Version(1, 9, 0, "beta-1");

    /**
     * Groovy 1.9.0 beta-3 version.
     */
    protected static final Version GROOVY_1_9_0_BETA3 = new Version(1, 9, 0, "beta-3");

    /**
     * Groovy 1.8.3 version.
     */
    protected static final Version GROOVY_1_8_3 = new Version(1, 8, 3);

    /**
     * The encoding of source files.
     *
     * @parameter default-value="${project.build.sourceEncoding}"
     */
    protected String sourceEncoding;

    /**
     * The file extensions of Groovy source files.
     * @since 1.0-beta-2
     *
     * @parameter
     */
    protected Set<String> scriptExtensions;

    /**
     * The Groovy compiler bytecode compatibility.  One of
     * <ul>
     *   <li>1.4</li>
     *   <li>1.5</li>
     *   <li>1.6</li>
     *   <li>1.7</li>
     *   <li>1.8</li>
     * </ul>
     * Using 1.6 or 1.7 requires Groovy >= 2.1.3, and using 1.8 requires Groovy >= 2.3.3.
     * If an invalid selection is made, Groovy will default to VM determined
     * version (1.4 or 1.5).
     * @since 1.0-beta-3
     *
     * @parameter property="maven.compiler.target" default-value="1.5"
     */
    protected String targetBytecode;

    /**
     * Whether Groovy compiler should be set to debug.
     *
     * @parameter default-value="false"
     */
    protected boolean debug;

    /**
     * Whether Groovy compiler should be set to verbose.
     *
     * @parameter default-value="false"
     */
    protected boolean verbose;

    /**
     * Groovy compiler warning level.  Should be one of:
     * <dl>
     *   <dt>0</dt>
     *     <dd>None</dd>
     *   <dt>1</dt>
     *     <dd>Likely Errors</dd>
     *   <dt>2</dt>
     *     <dd>Possible Errors</dd>
     *   <dt>3</dt>
     *     <dd>Paranoia</dd>
     * </dl>
     *
     * @parameter default-value="1"
     */
    protected int warningLevel;

    /**
     * Groovy compiler error tolerance (the number of non-fatal errors
     * (per unit) that should be tolerated before compilation is aborted).
     *
     * @parameter default-value="0"
     */
    protected int tolerance;


    /**
     * The ClassWrangler to use to work with Groovy classes.
     *
     * @component role-hint="ClassWrangler-Compile"
     */
    protected ClassWrangler classWrangler;

    /**
     * Performs the stub generation on the specified source files.
     *
     * @param stubSources the sources to perform stub generation on
     * @param outputDirectory the directory to write the stub files to
     * @throws ClassNotFoundException when a class needed for stub generation cannot be found
     * @throws InstantiationException when a class needed for stub generation cannot be instantiated
     * @throws IllegalAccessException when a method needed for stub generation cannot be accessed
     * @throws InvocationTargetException when a reflection invocation needed for stub generation cannot be completed
     * @throws MalformedURLException when a classpath element provides a malformed URL
     */
    protected synchronized void doStubGeneration(final Set<File> stubSources, final File outputDirectory) throws ClassNotFoundException, InvocationTargetException, IllegalAccessException, InstantiationException, MalformedURLException {
        logPluginClasspath();
        classWrangler.logGroovyVersion(mojoExecution.getMojoDescriptor().getGoal());

        if (stubSources == null || stubSources.isEmpty()) {
            getLog().info("No sources specified for stub generation.  Skipping.");
            return;
        }

        if (!groovyVersionSupportsAction(classWrangler)) {
            getLog().error("Your Groovy version (" + classWrangler.getGroovyVersionString() + ") doesn't support stub generation.  The minimum version of Groovy required is " + minGroovyVersion + ".  Skipping stub generation.");
            return;
        }

        // get classes we need with reflection
        Class<?> compilerConfigurationClass = classWrangler.getClass("org.codehaus.groovy.control.CompilerConfiguration");
        Class<?> javaStubCompilationUnitClass = classWrangler.getClass("org.codehaus.groovy.tools.javac.JavaStubCompilationUnit");
        Class<?> groovyClassLoaderClass = classWrangler.getClass("groovy.lang.GroovyClassLoader");

        // setup stub generation options
        Object compilerConfiguration = setupCompilerConfiguration(outputDirectory, compilerConfigurationClass);
        Object groovyClassLoader = classWrangler.invokeConstructor(classWrangler.findConstructor(groovyClassLoaderClass, ClassLoader.class, compilerConfigurationClass), classWrangler.getClassLoader(), compilerConfiguration);
        Object javaStubCompilationUnit = classWrangler.invokeConstructor(classWrangler.findConstructor(javaStubCompilationUnitClass, compilerConfigurationClass, groovyClassLoaderClass, File.class), compilerConfiguration, groovyClassLoader, outputDirectory);

        // add Groovy sources
        addGroovySources(stubSources, compilerConfigurationClass, javaStubCompilationUnitClass, compilerConfiguration, javaStubCompilationUnit);

        // generate the stubs
        classWrangler.invokeMethod(classWrangler.findMethod(javaStubCompilationUnitClass, "compile"), javaStubCompilationUnit);

        // log generated stubs
        getLog().info("Generated " + getStubs().size() + " stub" + (getStubs().size() > 1 || getStubs().size() == 0 ? "s" : "") + ".");
    }

    /**
     * Sets up the CompilerConfiguration to use for stub generation.
     *
     * @param outputDirectory the directory to write the stub files to
     * @param compilerConfigurationClass the CompilerConfiguration class
     * @return the CompilerConfiguration to use for stub generation
     * @throws InstantiationException when a class needed for stub generation cannot be instantiated
     * @throws IllegalAccessException when a method needed for stub generation cannot be accessed
     * @throws InvocationTargetException when a reflection invocation needed for stub generation cannot be completed
     */
    protected Object setupCompilerConfiguration(final File outputDirectory, final Class compilerConfigurationClass) throws InvocationTargetException, IllegalAccessException, InstantiationException {
        Object compilerConfiguration = classWrangler.invokeConstructor(classWrangler.findConstructor(compilerConfigurationClass));
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setDebug", boolean.class), compilerConfiguration, debug);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setVerbose", boolean.class), compilerConfiguration, verbose);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setWarningLevel", int.class), compilerConfiguration, warningLevel);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setTolerance", int.class), compilerConfiguration, tolerance);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setTargetBytecode", String.class), compilerConfiguration, targetBytecode);
        if (sourceEncoding != null) {
            classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setSourceEncoding", String.class), compilerConfiguration, sourceEncoding);
        }
        Map<String, Object> options = new HashMap<String, Object>();
        options.put("stubDir", outputDirectory);
        options.put("keepStubs", Boolean.TRUE);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setJointCompilationOptions", Map.class), compilerConfiguration, options);

        return compilerConfiguration;
    }

    /**
     * Adds the Groovy sources to the CompilationUnit.
     *
     * @param stubSources the sources to perform stub generation on
     * @param compilerConfigurationClass the CompilerConfiguration class
     * @param javaStubCompilationUnitClass the JavaStubCompilationUnit class
     * @param compilerConfiguration the CompilerConfiguration to use for stub generation
     * @param javaStubCompilationUnit the JavaStubCompilationUnit to use for stub generation
     * @throws IllegalAccessException when a method needed for stub generation cannot be accessed
     * @throws InvocationTargetException when a reflection invocation needed for stub generation cannot be completed
     */
    protected void addGroovySources(final Set<File> stubSources, final Class<?> compilerConfigurationClass, final Class<?> javaStubCompilationUnitClass, final Object compilerConfiguration, final Object javaStubCompilationUnit) throws InvocationTargetException, IllegalAccessException {
        Set<String> scriptExtensions = new HashSet<String>();
        for (File stubSource : stubSources) {
            scriptExtensions.add(FileUtils.getFileExtension(stubSource));
        }
        getLog().debug("Detected Groovy file extensions: " + scriptExtensions + ".");
        if (supportsSettingExtensions()) {
            classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setScriptExtensions", Set.class), compilerConfiguration, scriptExtensions);
        }
        getLog().debug("Adding Groovy to generate stubs for:");
        for (File stubSource : stubSources) {
            getLog().debug("    " + stubSource);
            if (supportsSettingExtensions()) {
                classWrangler.invokeMethod(classWrangler.findMethod(javaStubCompilationUnitClass, "addSource", File.class), javaStubCompilationUnit, stubSource);
            } else {
                DotGroovyFile dotGroovyFile = new DotGroovyFile(stubSource);
                dotGroovyFile.setScriptExtensions(scriptExtensions);
                classWrangler.invokeMethod(classWrangler.findMethod(javaStubCompilationUnitClass, "addSource", File.class), javaStubCompilationUnit, dotGroovyFile);
            }
        }
    }

    protected boolean supportsSettingExtensions() {
        return groovyAtLeast(classWrangler, GROOVY_1_8_3) && (groovyOlderThan(classWrangler, GROOVY_1_9_0_BETA1) || groovyNewerThan(classWrangler, GROOVY_1_9_0_BETA3));
    }

    /**
     * This is a fix for http://jira.codehaus.org/browse/MGROOVY-187
     * It modifies the dates of the created stubs to 1/1/1970, ensuring that
     * the Java compiler will not overwrite perfectly good compiled Groovy
     * just because it has a newer source stub.  Basically, this prevents the
     * stubs from causing a side effect with the Java compiler, but still
     * allows stubs to work with JavaDoc.
     *
     * @param stubs the files on which to reset the modified date
     */
    protected void resetStubModifiedDates(final Set<File> stubs) {
        for (File stub : stubs) {
            boolean success = stub.setLastModified(0L);
            if (!success) {
                getLog().warn("Unable to set modified time on stub " + stub.getAbsolutePath() + ".");
            }
        }
    }

}
