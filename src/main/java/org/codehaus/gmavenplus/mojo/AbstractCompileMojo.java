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

import org.codehaus.gmavenplus.model.Version;
import org.codehaus.gmavenplus.util.ClassWrangler;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.security.CodeSource;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * The base compile mojo, which all compile mojos extend.
 *
 * @author Keegan Witt
 * @since 1.0-beta-1
 */
public abstract class AbstractCompileMojo extends AbstractGroovySourcesMojo {

    /**
     * Groovy 2.3.3 version.
     */
    protected static final Version GROOVY_2_3_3 = new Version(2, 3, 3);

    /**
     * Groovy 2.1.3 version.
     */
    protected static final Version GROOVY_2_1_3 = new Version(2, 1, 3);

    /**
     * Groovy 2.1.0 beta-1 version.
     */
    protected static final Version GROOVY_2_1_0_BETA1 = new Version(2, 1, 0, "beta-1");

    /**
     * Groovy 2.0.0 beta-3 version.
     */
    protected static final Version GROOVY_2_0_0_BETA3 = new Version(2, 0, 0, "beta-3");

    /**
     * Groovy 1.6.0 version.
     */
    protected static final Version GROOVY_1_6_0 = new Version(1, 6, 0);

    /**
     * The location for the compiled classes.
     *
     * @parameter default-value="${project.build.outputDirectory}"
     */
    protected File outputDirectory;

    /**
     * The location for the compiled test classes.
     *
     * @parameter default-value="${project.build.testOutputDirectory}"
     */
    protected File testOutputDirectory;

    /**
     * The encoding of source files.
     *
     * @parameter default-value="${project.build.sourceEncoding}"
     */
    protected String sourceEncoding;

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
     * Groovy compiler error tolerance
     * (the number of non-fatal errors (per unit) that should be tolerated
     * before compilation is aborted).
     *
     * @parameter default-value="0"
     */
    protected int tolerance;

    /**
     * Whether to support invokeDynamic (requires Java 7 or greater and Groovy
     * indy 2.0.0-beta-3 or greater).
     *
     * @parameter property="invokeDynamic" default-value="false"
     */
    protected boolean invokeDynamic;

    /**
     * A <a href="http://groovy-lang.org/dsls.html#compilation-customizers">script</a>
     * for tweaking the configuration options (requires Groovy 2.1.0-beta-1
     * or greater).  Note that its encoding must match your source encoding.
     *
     * @parameter property="configScript"
     */
    protected File configScript;

    /**
     * Performs compilation of compile mojos.
     *
     * @param classWrangler the ClassWrangler to use to access Groovy classes
     * @param sources the sources to compile
     * @param compileOutputDirectory the directory to write the compiled class files to
     * @throws ClassNotFoundException when a class needed for compilation cannot be found
     * @throws InstantiationException when a class needed for compilation cannot be instantiated
     * @throws IllegalAccessException when a method needed for compilation cannot be accessed
     * @throws InvocationTargetException when a reflection invocation needed for compilation cannot be completed
     * @throws MalformedURLException when a classpath element provides a malformed URL
     */
    @SuppressWarnings("unchecked")
    protected synchronized void doCompile(final ClassWrangler classWrangler, final Set<File> sources, final File compileOutputDirectory)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException, InvocationTargetException, MalformedURLException {
        logPluginClasspath();
        classWrangler.logGroovyVersion(mojoExecution.getMojoDescriptor().getGoal());

        if (sources == null || sources.isEmpty()) {
            getLog().info("No sources specified for compilation.  Skipping.");
            return;
        }

        if (groovyVersionSupportsAction(classWrangler)) {
            verifyGroovyVersionSupportsTargetBytecode(classWrangler);
        } else {
            getLog().error("Your Groovy version (" + classWrangler.getGroovyVersionString() + ") doesn't support compilation.  The minimum version of Groovy required is " + minGroovyVersion + ".  Skipping compiling.");
            return;
        }

        // get classes we need with reflection
        Class<?> compilerConfigurationClass = classWrangler.getClass("org.codehaus.groovy.control.CompilerConfiguration");
        Class<?> compilationUnitClass = classWrangler.getClass("org.codehaus.groovy.control.CompilationUnit");
        Class<?> groovyClassLoaderClass = classWrangler.getClass("groovy.lang.GroovyClassLoader");

        // setup compile options
        Object compilerConfiguration = setupCompilerConfiguration(classWrangler, compileOutputDirectory, compilerConfigurationClass);
        Object groovyClassLoader = classWrangler.invokeConstructor(classWrangler.findConstructor(groovyClassLoaderClass, ClassLoader.class, compilerConfigurationClass), classWrangler.getClassLoader(), compilerConfiguration);
        Object transformLoader = classWrangler.invokeConstructor(classWrangler.findConstructor(groovyClassLoaderClass, ClassLoader.class), classWrangler.getClassLoader());

        // add Groovy sources
        Object compilationUnit = setupCompilationUnit(classWrangler, sources, compilerConfigurationClass, compilationUnitClass, groovyClassLoaderClass, compilerConfiguration, groovyClassLoader, transformLoader);

        // compile the classes
        classWrangler.invokeMethod(classWrangler.findMethod(compilationUnitClass, "compile"), compilationUnit);

        // log compiled classes
        List classes = (List) classWrangler.invokeMethod(classWrangler.findMethod(compilationUnitClass, "getClasses"), compilationUnit);
        getLog().info("Compiled " + classes.size() + " file" + (classes.size() > 1 || classes.size() == 0 ? "s" : "") + ".");
    }

    /**
     * Sets up the CompilationUnit to use for compilation.
     *
     * @param classWrangler the ClassWrangler to use to access Groovy classes
     * @param sources the sources to compile
     * @param compilerConfigurationClass the CompilerConfiguration class
     * @param compilationUnitClass the CompilationUnit class
     * @param groovyClassLoaderClass the GroovyClassLoader class
     * @param compilerConfiguration the CompilerConfiguration
     * @param groovyClassLoader the GroovyClassLoader
     * @param transformLoader the GroovyClassLoader to use for transformation
     * @return the CompilationUnit
     * @throws InstantiationException when a class needed for setting up compilation unit cannot be instantiated
     * @throws IllegalAccessException when a method needed for setting up compilation unit cannot be accessed
     * @throws InvocationTargetException when a reflection invocation needed for setting up compilation unit cannot be completed
     */
    protected Object setupCompilationUnit(final ClassWrangler classWrangler, final Set<File> sources, final Class<?> compilerConfigurationClass, final Class<?> compilationUnitClass, final Class<?> groovyClassLoaderClass, final Object compilerConfiguration, final Object groovyClassLoader, final Object transformLoader) throws InvocationTargetException, IllegalAccessException, InstantiationException {
        Object compilationUnit;
        if (groovyAtLeast(classWrangler, GROOVY_1_6_0)) {
            compilationUnit = classWrangler.invokeConstructor(classWrangler.findConstructor(compilationUnitClass, compilerConfigurationClass, CodeSource.class, groovyClassLoaderClass, groovyClassLoaderClass), compilerConfiguration, null, groovyClassLoader, transformLoader);
        } else {
            compilationUnit = classWrangler.invokeConstructor(classWrangler.findConstructor(compilationUnitClass, compilerConfigurationClass, CodeSource.class, groovyClassLoaderClass), compilerConfiguration, null, groovyClassLoader);
        }
        getLog().debug("Adding Groovy to compile:");
        for (File source : sources) {
            getLog().debug("    " + source);
            classWrangler.invokeMethod(classWrangler.findMethod(compilationUnitClass, "addSource", File.class), compilationUnit, source);
        }

        return compilationUnit;
    }

    /**
     * Sets up the CompilationConfiguration to use for compilation.
     *
     * @param classWrangler the ClassWrangler to use to access Groovy classes
     * @param compileOutputDirectory the directory to write the compiled classes to
     * @param compilerConfigurationClass the CompilerConfiguration class
     * @return the CompilerConfiguration
     * @throws ClassNotFoundException when a class needed for setting up CompilerConfiguration cannot be found
     * @throws InstantiationException when a class needed for setting up CompilerConfiguration cannot be instantiated
     * @throws IllegalAccessException when a method needed for setting up CompilerConfiguration cannot be accessed
     * @throws InvocationTargetException when a reflection invocation needed for setting up CompilerConfiguration cannot be completed
     */
    @SuppressWarnings("unchecked")
    protected Object setupCompilerConfiguration(final ClassWrangler classWrangler, final File compileOutputDirectory, final Class<?> compilerConfigurationClass) throws InvocationTargetException, IllegalAccessException, InstantiationException, ClassNotFoundException {
        Object compilerConfiguration = classWrangler.invokeConstructor(classWrangler.findConstructor(compilerConfigurationClass));
        if (configScript != null) {
            if (groovyAtLeast(classWrangler, GROOVY_2_1_0_BETA1) && configScript.exists()) {
                Class<?> bindingClass = classWrangler.getClass("groovy.lang.Binding");
                Class<?> importCustomizerClass = classWrangler.getClass("org.codehaus.groovy.control.customizers.ImportCustomizer");
                Class<?> groovyShellClass = classWrangler.getClass("groovy.lang.GroovyShell");

                Object binding = classWrangler.invokeConstructor(classWrangler.findConstructor(bindingClass));
                classWrangler.invokeMethod(classWrangler.findMethod(bindingClass, "setVariable", String.class, Object.class), binding, "configuration", compilerConfiguration);
                Object shellCompilerConfiguration = classWrangler.invokeConstructor(classWrangler.findConstructor(compilerConfigurationClass));
                Object importCustomizer = classWrangler.invokeConstructor(classWrangler.findConstructor(importCustomizerClass));
                classWrangler.invokeMethod(classWrangler.findMethod(importCustomizerClass, "addStaticStar", String.class), importCustomizer, "org.codehaus.groovy.control.customizers.builder.CompilerCustomizationBuilder");
                List compilationCustomizers = (List) classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "getCompilationCustomizers"), shellCompilerConfiguration);
                compilationCustomizers.add(importCustomizer);
                Object shell = classWrangler.invokeConstructor(classWrangler.findConstructor(groovyShellClass, bindingClass, compilerConfigurationClass), binding, shellCompilerConfiguration);
                getLog().debug("Using configuration script " + configScript + " for compilation.");
                classWrangler.invokeMethod(classWrangler.findMethod(groovyShellClass, "evaluate", File.class), shell, configScript);
            } else {
                getLog().warn("Requested to use configScript, but your Groovy version (" + classWrangler.getGroovyVersionString() + ") doesn't support it (must be " + GROOVY_2_1_0_BETA1 + " or newer).  Ignoring configScript parameter.");
            }
        }
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setDebug", boolean.class), compilerConfiguration, debug);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setVerbose", boolean.class), compilerConfiguration, verbose);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setWarningLevel", int.class), compilerConfiguration, warningLevel);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setTolerance", int.class), compilerConfiguration, tolerance);
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setTargetBytecode", String.class), compilerConfiguration, targetBytecode);
        if (sourceEncoding != null) {
            classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setSourceEncoding", String.class), compilerConfiguration, sourceEncoding);
        }
        classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "setTargetDirectory", String.class), compilerConfiguration, compileOutputDirectory.getAbsolutePath());
        if (invokeDynamic) {
            if (groovyAtLeast(classWrangler, GROOVY_2_0_0_BETA3)) {
                if (classWrangler.isGroovyIndy()) {
                    if (isJavaSupportIndy()) {
                        Map<String, Boolean> optimizationOptions = (Map<String, Boolean>) classWrangler.invokeMethod(classWrangler.findMethod(compilerConfigurationClass, "getOptimizationOptions"), compilerConfiguration);
                        optimizationOptions.put("indy", true);
                        optimizationOptions.put("int", false);
                    } else {
                        getLog().warn("Requested to use to use invokedynamic, but your Java version (" + getJavaVersionString() + ") doesn't support it.  Ignoring invokeDynamic parameter.");
                    }
                } else {
                    getLog().warn("Requested to use invokedynamic, but your Groovy version doesn't support it (must use have indy classifier).  Ignoring invokeDynamic parameter.");
                }
            } else {
                getLog().warn("Requested to use invokeDynamic, but your Groovy version (" + classWrangler.getGroovyVersionString() + ") doesn't support it (must be " + GROOVY_2_0_0_BETA3 + " or newer).  Ignoring invokeDynamic parameter.");
            }
        }

        return compilerConfiguration;
    }

    /**
     * Throws an exception if targetBytecode is not supported with this version of Groovy.
     *
     * @param classWrangler the ClassWrangler to use to access Groovy classes
     */
    protected void verifyGroovyVersionSupportsTargetBytecode(final ClassWrangler classWrangler) {
        if ("1.9".equals(targetBytecode)) {
            throw new IllegalArgumentException("Target bytecode 1.9 is not yet supported.");
        } else if ("1.8".equals(targetBytecode)) {
            if (groovyOlderThan(classWrangler, GROOVY_2_3_3)) {
                throw new IllegalArgumentException("Target bytecode 1.8 requires Groovy " + GROOVY_2_3_3 + ".");
            }
        } else if ("1.7".equals(targetBytecode) || "1.6".equals(targetBytecode)) {
            if (groovyOlderThan(classWrangler, GROOVY_2_1_3)) {
                throw new IllegalArgumentException("Target bytecode 1.6 and 1.7 require Groovy " + GROOVY_2_1_3 + ".");
            }
        } else if (!"1.5".equals(targetBytecode) && !"1.4".equals(targetBytecode)) {
            throw new IllegalArgumentException("Unrecognized target bytecode.");
        }
    }

}
