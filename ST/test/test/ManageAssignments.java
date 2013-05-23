package test;

import net.sourceforge.jwebunit.junit.WebTester;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Gustavo German Soria
 */
public class ManageAssignments {

    private WebTester tester;
    private String previousValue = null;

    public ManageAssignments() {
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

            tester.setTextField("username", "teacher1");
            tester.setTextField("password", "nonlaso");
            tester.submit();

            tester.assertMatch("topolino topolino's Classes");
            tester.clickLinkWithText("class1");

            tester.assertMatch("Class Settings");
            tester.clickLinkWithText("Assignments");

            tester.setWorkingForm("assignments");
            tester.assertCheckboxPresent("delete[]", "1");
            tester.checkCheckbox("delete[]", "1");
            tester.clickButtonWithText("Edit");

            tester.assertMatch("Edit Assignment");
            tester.setTextField("task", previousValue);

            tester.clickButtonWithText("Edit Assignment");
        }
    }

    @Test
    public void VulnerabilityManageClass() {
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher1");
        tester.setTextField("password", "nonlaso");
        tester.submit();

        tester.assertMatch("topolino topolino's Classes");
        tester.clickLinkWithText("class1");

        tester.assertMatch("Class Settings");
        tester.clickLinkWithText("Assignments");

        tester.setWorkingForm("assignments");
        tester.assertCheckboxPresent("delete[]", "1");
        tester.checkCheckbox("delete[]", "1");
        tester.clickButtonWithText("Edit");

        tester.assertMatch("Edit Assignment");
        previousValue = tester.getElementByXPath("html//textarea[@name='task']").getTextContent();
        tester.setTextField("task", "<a href=www.gazzetta.it>Real Task</a>");

        tester.clickButtonWithText("Edit Assignment");

        tester.assertLinkNotPresentWithText("Real Task");
    }
}
