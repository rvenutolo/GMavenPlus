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

import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.codehaus.gmavenplus.model.Version;

import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;


/**
 * Generates stubs for the main Groovy sources and adds them to Maven's sources
 * for the Maven compiler plugin to find.
 * Note that this mojo requires Groovy >= 1.8.2.
 *
 * @author Keegan Witt
 * @since 1.0-beta-1
 *
 * @goal generateStubs
 * @phase generate-sources
 * @requiresDependencyResolution compile
 * @threadSafe
 */
public class GenerateStubsMojo extends AbstractGenerateStubsMojo {

    /**
     * Groovy 1.8.2 version.
     */
    protected static final Version GROOVY_1_8_2 = new Version(1, 8, 2);

    /**
     * Executes this mojo.
     *
     * @throws MojoExecutionException If an unexpected problem occurs. Throwing this exception causes a "BUILD ERROR" message to be displayed
     * @throws MojoFailureException If an expected problem (such as a compilation failure) occurs. Throwing this exception causes a "BUILD FAILURE" message to be displayed
     */
    public void execute() throws MojoExecutionException, MojoFailureException {
        minGroovyVersion = GROOVY_1_8_2;
        try {
            try {
                getLog().debug("Project compile classpath:\n" + project.getCompileClasspathElements());
            } catch (DependencyResolutionRequiredException e) {
                getLog().warn("Unable to log project compile classpath", e);
            }
            classWrangler.initialize(project.getCompileClasspathElements(), getLog());
            doStubGeneration(getSources(), stubsOutputDirectory);
            resetStubModifiedDates(getStubs());
            getLog().info("Generated " + getStubs().size() + " stub" + (getStubs().size() > 1 || getStubs().size() == 0 ? "s" : "") + ".");

            // add stubs to project source so the Maven Compiler Plugin can find them
            project.addCompileSourceRoot(stubsOutputDirectory.getAbsolutePath());
        } catch (ClassNotFoundException e) {
            throw new MojoExecutionException("Unable to get a Groovy class from classpath.  Do you have Groovy as a compile dependency in your project?", e);
        } catch (InvocationTargetException e) {
            throw new MojoExecutionException("Error occurred while calling a method on a Groovy class from classpath.", e);
        } catch (InstantiationException e) {
            throw new MojoExecutionException("Error occurred while instantiating a Groovy class from classpath.", e);
        } catch (IllegalAccessException e) {
            throw new MojoExecutionException("Unable to access a method on a Groovy class from classpath.", e);
        } catch (DependencyResolutionRequiredException e) {
            throw new MojoExecutionException("Compile dependencies weren't resolved.", e);
        } catch (MalformedURLException e) {
            throw new MojoExecutionException("Unable to add project compile dependencies to classpath.", e);
        }
    }

}
