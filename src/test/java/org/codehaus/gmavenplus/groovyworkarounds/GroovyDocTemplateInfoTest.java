package org.codehaus.gmavenplus.groovyworkarounds;

import org.codehaus.gmavenplus.model.Version;
import org.codehaus.gmavenplus.util.ClassWrangler;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;


/**
 * Unit tests for the GroovyDocTemplateInfo class.
 *
 * @author Keegan Witt
 */
public class GroovyDocTemplateInfoTest {

    @Test
    public void testDefaultDocTemplatesWithGroovy1_6_2() {
        Version version = new Version(1, 6, 2);
        ClassWrangler classWrangler = spy(new ClassWrangler());
        doReturn(version.toString()).when(classWrangler).getGroovyVersionString();
        when(classWrangler.getGroovyVersion()).thenCallRealMethod();
        GroovyDocTemplateInfo groovyDocTemplateInfo = new GroovyDocTemplateInfo(classWrangler);
        assertArrayEquals(new String[] {
                groovyDocTemplateInfo.templateBaseDir + "topLevel/index.html",
                groovyDocTemplateInfo.templateBaseDir + "topLevel/overview-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "topLevel/allclasses-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "topLevel/overview-summary.html",
                groovyDocTemplateInfo.templateBaseDir + "topLevel/help-doc.html",
                groovyDocTemplateInfo.templateBaseDir + "topLevel/index-all.html",
                groovyDocTemplateInfo.templateBaseDir + "topLevel/deprecated-list.html",
                groovyDocTemplateInfo.templateBaseDir + "topLevel/stylesheet.css",
                groovyDocTemplateInfo.templateBaseDir + "topLevel/inherit.gif",
                GroovyDocTemplateInfo.DOCGEN_BASEDIR + "groovy.ico"
        }, groovyDocTemplateInfo.defaultDocTemplates());
    }

    @Test
    public void testDefaultDocTemplatesWithGroovy1_6_0() {
        Version version = new Version(1, 6, 0);
        ClassWrangler classWrangler = spy(new ClassWrangler());
        doReturn(version.toString()).when(classWrangler).getGroovyVersionString();
        when(classWrangler.getGroovyVersion()).thenCallRealMethod();
        GroovyDocTemplateInfo groovyDocTemplateInfo = new GroovyDocTemplateInfo(classWrangler);
        assertArrayEquals(new String[] {
                groovyDocTemplateInfo.templateBaseDir + "top-level/index.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/overview-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/allclasses-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/overview-summary.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/help-doc.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/index-all.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/deprecated-list.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/stylesheet.css",
                groovyDocTemplateInfo.templateBaseDir + "top-level/inherit.gif"}, groovyDocTemplateInfo.defaultDocTemplates());
    }

    @Test
    public void testDefaultDocTemplatesWithGroovy1_6_0_RC2() {
        Version version = new Version(1, 6, 0, "RC-2");
        ClassWrangler classWrangler = spy(new ClassWrangler());
        doReturn(version.toString()).when(classWrangler).getGroovyVersionString();
        when(classWrangler.getGroovyVersion()).thenCallRealMethod();
        GroovyDocTemplateInfo groovyDocTemplateInfo = new GroovyDocTemplateInfo(classWrangler);
        assertArrayEquals(new String[] {
                groovyDocTemplateInfo.templateBaseDir + "top-level/index.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/overview-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/allclasses-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/overview-summary.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/stylesheet.css",
                groovyDocTemplateInfo.templateBaseDir + "top-level/inherit.gif"
        }, groovyDocTemplateInfo.defaultDocTemplates());
    }

    @Test
    public void testDefaultDocTemplatesWithGroovy1_5_0() {
        Version version = new Version(1, 5, 0);
        ClassWrangler classWrangler = spy(new ClassWrangler());
        doReturn(version.toString()).when(classWrangler).getGroovyVersionString();
        when(classWrangler.getGroovyVersion()).thenCallRealMethod();
        GroovyDocTemplateInfo groovyDocTemplateInfo = new GroovyDocTemplateInfo(classWrangler);
        assertArrayEquals(new String[] {
                groovyDocTemplateInfo.templateBaseDir + "top-level/index.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/overview-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/allclasses-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/overview-summary.html",
                groovyDocTemplateInfo.templateBaseDir + "top-level/stylesheet.css"
        }, groovyDocTemplateInfo.defaultDocTemplates());
    }

    @Test
    public void testDefaultPackageTemplatesWithGroovy1_6_2() {
        Version version = new Version(1, 6, 2);
        ClassWrangler classWrangler = spy(new ClassWrangler());
        doReturn(version.toString()).when(classWrangler).getGroovyVersionString();
        when(classWrangler.getGroovyVersion()).thenCallRealMethod();
        GroovyDocTemplateInfo groovyDocTemplateInfo = new GroovyDocTemplateInfo(classWrangler);
        assertArrayEquals(new String[] {
                groovyDocTemplateInfo.templateBaseDir + "packageLevel/package-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "packageLevel/package-summary.html"
        }, groovyDocTemplateInfo.defaultPackageTemplates());
    }

    @Test
    public void testDefaultPackageTemplatesWithGroovy1_5_0() {
        Version version = new Version(1, 5, 0);
        ClassWrangler classWrangler = spy(new ClassWrangler());
        doReturn(version.toString()).when(classWrangler).getGroovyVersionString();
        when(classWrangler.getGroovyVersion()).thenCallRealMethod();
        GroovyDocTemplateInfo groovyDocTemplateInfo = new GroovyDocTemplateInfo(classWrangler);
        assertArrayEquals(new String[] {
                groovyDocTemplateInfo.templateBaseDir + "package-level/package-frame.html",
                groovyDocTemplateInfo.templateBaseDir + "package-level/package-summary.html"
        }, groovyDocTemplateInfo.defaultPackageTemplates());
    }

    @Test
    public void testDefaultClassTemplatesWithGroovy1_6_2() {
        Version version = new Version(1, 6, 2);
        ClassWrangler classWrangler = spy(new ClassWrangler());
        doReturn(version.toString()).when(classWrangler).getGroovyVersionString();
        when(classWrangler.getGroovyVersion()).thenCallRealMethod();
        GroovyDocTemplateInfo groovyDocTemplateInfo = new GroovyDocTemplateInfo(classWrangler);
        assertArrayEquals(new String[] {groovyDocTemplateInfo.templateBaseDir + "classLevel/classDocName.html"}, groovyDocTemplateInfo.defaultClassTemplates());
    }

    @Test
    public void testDefaultClassTemplatesWithGroovy1_5_0() {
        Version version = new Version(1, 5, 0);
        ClassWrangler classWrangler = spy(new ClassWrangler());
        doReturn(version.toString()).when(classWrangler).getGroovyVersionString();
        when(classWrangler.getGroovyVersion()).thenCallRealMethod();
        GroovyDocTemplateInfo groovyDocTemplateInfo = new GroovyDocTemplateInfo(classWrangler);
        assertArrayEquals(new String[] {groovyDocTemplateInfo.templateBaseDir + "class-level/classDocName.html"}, groovyDocTemplateInfo.defaultClassTemplates());
    }

}
