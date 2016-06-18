/*
 * Copyright 2014 the original author or authors.
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

import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.codehaus.gmavenplus.util.ClassWrangler;
import org.codehaus.gmavenplus.util.NoExitSecurityManager;

import java.lang.reflect.InvocationTargetException;
import java.util.Set;


/**
 * Launches a Groovy console window bound to the current project.
 * Note that this mojo requires Groovy >= 1.5.0.
 * Note that it references the plugin classloader to pull in dependencies
 * Groovy didn't include (for things like Ant for AntBuilder, Ivy for @grab,
 * and Jansi for Groovysh).
 *
 * @author Keegan Witt
 * @since 1.1
 *
 * @goal console
 * @configurator include-project-test-dependencies
 * @requiresDependencyResolution test
 */
public class ConsoleMojo extends AbstractToolsMojo {

    /**
     * The ClassWrangler to use to work with Groovy classes.
     *
     * @component role-hint="ClassWrangler-Plugin"
     */
    protected ClassWrangler classWrangler;

    /**
     * Executes this mojo.
     *
     * @throws MojoExecutionException If an unexpected problem occurs. Throwing this exception causes a "BUILD ERROR" message to be displayed
     * @throws MojoFailureException If an expected problem (such as an invocation failure) occurs. Throwing this exception causes a "BUILD FAILURE" message to be displayed
     */
    public void execute() throws MojoExecutionException, MojoFailureException {
        classWrangler.initialize(Thread.currentThread().getContextClassLoader(), getLog());

        try {
            getLog().debug("Project test classpath:\n" + project.getTestClasspathElements());
        } catch (DependencyResolutionRequiredException e) {
            getLog().warn("Unable to log project test classpath", e);
        }
        logPluginClasspath();
        classWrangler.logGroovyVersion(mojoExecution.getMojoDescriptor().getGoal());

        if (groovyVersionSupportsAction(classWrangler)) {
            final SecurityManager sm = System.getSecurityManager();
            try {
                if (!allowSystemExits) {
                    System.setSecurityManager(new NoExitSecurityManager());
                }

                // get classes we need with reflection
                Class<?> consoleClass = classWrangler.getClass("groovy.ui.Console");
                Class<?> bindingClass = classWrangler.getClass("groovy.lang.Binding");

                // create console to run
                Object console = setupConsole(classWrangler, consoleClass, bindingClass);

                // run the console
                classWrangler.invokeMethod(classWrangler.findMethod(consoleClass, "run"), console);

                // TODO: for some reason instantiating AntBuilder before calling run() causes its stdout and stderr streams to not be captured by the Console
                bindAntBuilder(classWrangler, consoleClass, bindingClass, console);

                // wait for console to be closed
                Set<Thread> threadSet = Thread.getAllStackTraces().keySet();
                Thread[] threadArray = threadSet.toArray(new Thread[threadSet.size()]);
                Thread consoleThread = null;
                for (Thread thread : threadArray) {
                    if ("AWT-Shutdown".equals(thread.getName())) {
                        consoleThread = thread;
                        break;
                    }
                }
                if (consoleThread != null) {
                    try {
                        consoleThread.join();
                    } catch (InterruptedException e) {
                        throw new MojoExecutionException("Mojo interrupted while waiting for Console thread to end.", e);
                    }
                } else {
                    throw new MojoFailureException("Unable to locate Console thread to wait on.");
                }
            } catch (ClassNotFoundException e) {
                throw new MojoExecutionException("Unable to get a Groovy class from classpath.  Do you have Groovy as a compile dependency in your project or the plugin?", e);
            } catch (InvocationTargetException e) {
                if (e.getCause() instanceof NoClassDefFoundError && "org/apache/ivy/core/report/ResolveReport".equals(e.getCause().getMessage())) {
                    throw new MojoExecutionException("Groovy 1.7.6 and 1.7.7 have a dependency on Ivy to run the console.  Either change your Groovy version or add Ivy as a project or plugin dependency.", e);
                } else {
                    throw new MojoExecutionException("Error occurred while calling a method on a Groovy class from classpath.", e);
                }
            } catch (IllegalAccessException e) {
                throw new MojoExecutionException("Unable to access a method on a Groovy class from classpath.", e);
            } catch (InstantiationException e) {
                throw new MojoExecutionException("Error occurred while instantiating a Groovy class from classpath.", e);
            } finally {
                if (!allowSystemExits) {
                    System.setSecurityManager(sm);
                }
            }
        } else {
            getLog().error("Your Groovy version (" + classWrangler.getGroovyVersionString() + ") doesn't support running a console.  The minimum version of Groovy required is " + minGroovyVersion + ".  Skipping console startup.");
        }
    }

    /**
     * Binds a new AntBuilder to the project properties.
     *
     * @param classWrangler the ClassWrangler to use to access Groovy classes
     * @param consoleClass the groovy.ui.Console class to use
     * @param bindingClass the groovy.lang.Binding class to use
     * @param console the groovy.ui.Console object to use
     * @throws ClassNotFoundException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     * @throws InstantiationException
     */
    protected void bindAntBuilder(final ClassWrangler classWrangler, final Class<?> consoleClass, final Class<?> bindingClass, final Object console) throws ClassNotFoundException, IllegalAccessException, InvocationTargetException, InstantiationException {
        if (properties.containsKey("ant")) {
            Class<?> groovyShellClass = classWrangler.getClass("groovy.lang.GroovyShell");
            Object shell = classWrangler.getField(classWrangler.findField(consoleClass, "shell", groovyShellClass), console);
            Object binding = classWrangler.invokeMethod(classWrangler.findMethod(groovyShellClass, "getContext"), shell);
            Object antBuilder = classWrangler.invokeConstructor(classWrangler.findConstructor(classWrangler.getClass("groovy.util.AntBuilder")));
            if (bindPropertiesToSeparateVariables) {
                classWrangler.invokeMethod(classWrangler.findMethod(bindingClass, "setVariable", String.class, Object.class), binding, "ant", antBuilder);
            } else {
                properties.put("ant", antBuilder);
            }
        }
    }

    /**
     * Instantiates a Groovy Console.
     *
     * @param classWrangler the ClassWrangler to use to access Groovy classes
     * @param consoleClass the Console class
     * @param bindingClass the Binding class
     * @return the instantiated Console
     * @throws InstantiationException when a class needed for creating a console cannot be instantiated
     * @throws IllegalAccessException when a method needed for creating a console cannot be accessed
     * @throws InvocationTargetException when a reflection invocation needed for creating a console cannot be completed
     */
    protected Object setupConsole(final ClassWrangler classWrangler, final Class<?> consoleClass, final Class<?> bindingClass) throws InvocationTargetException, IllegalAccessException, InstantiationException {
        Object binding = classWrangler.invokeConstructor(classWrangler.findConstructor(bindingClass));
        initializeProperties(classWrangler);
        if (bindPropertiesToSeparateVariables) {
            for (Object k : properties.keySet()) {
                classWrangler.invokeMethod(classWrangler.findMethod(bindingClass, "setVariable", String.class, Object.class), binding, k, properties.get(k));
            }
        } else {
            classWrangler.invokeMethod(classWrangler.findMethod(bindingClass, "setVariable", String.class, Object.class), binding, "properties", properties);
        }

        return classWrangler.invokeConstructor(classWrangler.findConstructor(consoleClass, ClassLoader.class, bindingClass), Thread.currentThread().getContextClassLoader(), binding);
    }

}
