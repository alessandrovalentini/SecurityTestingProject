package test;

import net.sourceforge.jwebunit.junit.WebTester;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Gustavo German Soria
 */
public class ManageSemester {

    private WebTester tester;
    private String previousValue = null;

    public ManageSemester() {
    }

    @Before
    public void setUp() {
        tester = new WebTester();
        tester.setBaseUrl("http://localhost:8888/schoolmate/");
    }

    @After
    public void tearDown() {
        if (previousValue != null) {
            tester.beginAt("index.php");
            tester.assertMatch("Today's Message");

            tester.setTextField("username", "test");
            tester.setTextField("password", "test");
            tester.submit();

            tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("Semesters");

        tester.assertMatch("Manage Semesters");
        tester.setWorkingForm("semesters");
        tester.assertCheckboxPresent("delete[]", "2");
        tester.checkCheckbox("delete[]", "2");
        tester.clickButtonWithText("Edit");

        tester.assertMatch("Edit Semester");
        tester.setTextField("title", previousValue);

        tester.clickButtonWithText("Edit Semester");
        }
    }

    @Test
    public void VulnerabilityManageClass() {
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "test");
        tester.setTextField("password", "test");
        tester.submit();

        tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("Semesters");

        tester.assertMatch("Manage Semesters");
        tester.setWorkingForm("semesters");
        tester.assertCheckboxPresent("delete[]", "2");
        tester.checkCheckbox("delete[]", "2");
        tester.clickButtonWithText("Edit");

        tester.assertMatch("Edit Semester");
        previousValue = tester.getElementByXPath("//input[@type='text' and @name='title']").getAttribute("value");
        tester.setTextField("title", "<a href=as.it>b");

        tester.clickButtonWithText("Edit Semester");

        tester.assertLinkNotPresentWithText("b");
    }
}
