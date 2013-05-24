
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.InputElementFactory;

import org.junit.*;
import org.w3c.dom.html.HTMLElement;
import org.xml.sax.helpers.AttributesImpl;

import net.sourceforge.jwebunit.api.IElement;
import net.sourceforge.jwebunit.htmlunit.HtmlUnitElementImpl;
import net.sourceforge.jwebunit.junit.WebTester;

public class TestSchoolMate {

    private WebTester tester;
    private String previousValue = null;

    @Before
    public void prepare() {
        tester = new WebTester();
        tester.setBaseUrl("http://localhost/schoolmate/");
    }

    //Mariano Ceccato
            /*Index.php -> AddAssignament.php ($page2, hidden field)*/
    @Test
    public void testVulnerability11() {
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher");
        tester.setTextField("password", "teacher");
        tester.submit();
        tester.assertMatch("teacher's Classes"); //<- Check
        tester.clickLinkWithText("Class3"); // course name
        tester.assertMatch("Class Settings");
        tester.clickLinkWithText("Assignments");

        tester.assertMatch("Manage Assignments");
        tester.setHiddenField("page2",
                "<a href=\"http://www.google.it\">malicious link</a> <br' "); //malicious link
        //tester.clickButton("Add");//<- this button override the attack!
        //tester.submit(); //<- does not work
        IElement button = tester.getElementByXPath("input[@value='Add']"); //<-
        button.getAttribute("onclick");

        String oldValue = button.getAttribute("onClick") + "";
        String newValue = "document.assignment.submit()";
        button.setAttribute("onClick", newValue);
        System.err.println(oldValue);

        addSubmitButton("//form[@]");
        tester.assertMatch("Add New Assignament");
        tester.assertLinkNotPresentWithText("malicious link"); //maliciouse link
    }

    private void addSubmitButton(String expression) {
        IElement wrapper = tester.getElementByXPath(expression);
        DomElement form = ((HtmlUnitElementImpl) wrapper).getHtmlElement();
        AttributesImpl attributes = new AttributesImpl();
        attributes.addAttribute("", "", "type", "", "submit");
        HTMLElement submit;
        submit = (HTMLElement) InputElementFactory.instance.createElement(form.getPage(), "input", attributes);

        System.err.println(form);
    }
    //-----------------------------------------------------------------------------

    @Test
    public void testVulnerability13() {
        tester.assertCommentPresent("Not Yet Implemented");
    }

    @Test
    public void testVulnerability18() {
        //Vulnerability 18-19
        tester.assertCommentPresent("Not Yet Implemented");

    }

    @Test
    public void testVulnerability30() {
        /*Vulnerability 30-31, read unsanitized value from DB
         *"SELECT coursename FROM courses WHERE courseid = '$_POST[selectclass]'
         *inject code in coursename of "student" hack instead con Class1 
         *<a href=ask.it>C</a>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();

        //Sql injection
        tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("Classes");
        tester.assertCheckboxPresent("delete[]", "5");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Class");
        tester.setTextField("title", "<a href=1.1.1.1:80>C");
        tester.clickButtonWithText("Edit Class");

        //Check injection
        tester.assertLinkNotPresentWithText("C");
    }

    @Test
    public void testVulnerability37() {
        /*Vulnerability 37, EditAssignment.php
         * 
         * */
        tester.assertCommentPresent("Not Yet Implemented");

    }

    @Test
    public void testVulnerability41() {
        /*Vulnerability 41, EditAnnouncement.php
         * SELECT * FROM schoolbulletins WHERE sbulletinid = $id[0]
         * Fields 1,2, 3 -> Title, Message, Date (safe)
         * Title: <a href=as.it>T
         * Message: <a href="http://www.microsoft.com/">Malicious link</a>
         */

        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();

        //Sql injection
        tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("Classes");
        tester.assertCheckboxPresent("delete[]", "7");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Class");
        tester.setTextField("title", "<a href=as.it>T");
        tester.setTextField("message",
                "<a href='http://www.microsoft.com/'>Malicious link</a>");
        tester.clickButtonWithText("Add announcement");

        //Check injection
        tester.assertLinkNotPresentWithText("T");
        tester.assertLinkNotPresentWithText("Malicious link");

    }

    @Test
    public void testVulnerability44() {
        /*Vulnerability 44, EditTerm.php
         * SELECT title, startdate, enddate FROM terms WHERE termid = $id[0]
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Sql injection
        tester.clickLinkWithText("Terms");
        tester.assertCheckboxPresent("delete[]", "4");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Term");
        tester.setTextField("title", "<a href=as.it>T");
        tester.clickButtonWithText("Edit Term");

        //Check injection
        tester.assertLinkNotPresentWithText("T");
    }

    //Mariano Ceccato
    @Test
    public void testVulnerability54() {
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin ");
        tester.setTextField("password", "admin");
        tester.submit();

        tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("School");

        tester.assertMatch("Manage School Information");
        previousValue = tester.getElementByXPath(
                "html//textarea[@name='sitetext']").getTextContent();
        tester.setTextField("sitetext",
                "<a href=http://unitn.it>malicious link</a>");
        tester.clickButtonWithText(" Update ");

        tester.clickLinkWithText("Log Out");
        tester.assertMatch("Today's Message");

        tester.assertLinkNotPresentWithText("malicious link");
    }

    @Test
    public void testVulnerability76() {
        /*Vulnerability 76, EditGrade.php
         * SELECT fname, lname FROM students WHERE studentid =\''.$id[0].'\'
         * fname, lname (student[0], studnet[1]) 
         */

        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher");
        tester.setTextField("password", "teacher");
        tester.submit();

        //SQL injection on name and surname as admin

        //Check Injection
        tester.assertMatch("teacher teacher's Classes");
        tester.clickLinkWithExactText("Class1");
        tester.clickLinkWithText("Grades");
        tester.assertCheckboxPresent("delete[]", "2");
        tester.clickButtonWithText("Edit");

        tester.assertLinkNotPresentWithText("/*Injection link*/");
    }

    @Test
    public void testVulnerability85() {
        /*Vulnerability 85, EditSemester.php ----------> Già fixata?
         * SELECT termid,title FROM terms
         * <option value='$terms[0]'>$terms[1]</option>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();

        //Sql injection
        tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("Semesters");
        tester.assertCheckboxPresent("delete[]", "3");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Semesters");
        tester.setTextField("title", "<a href=as.it>S");
        tester.clickButtonWithText("Edit Semesters");

        //Check injection
        tester.assertLinkNotPresentWithText("S");
    }

    @Test
    public void testVulnerability87() {
        //Vulnerability 87,88 ViewClassSettings.php
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "student");
        tester.setTextField("password", "student");
        tester.submit();
        tester.assertMatch("Student Student's Classes");


        //Go to injection
        tester.clickLinkWithText("Class1");
        tester.setHiddenField("selectclass",
                "<a href=\"http://www.microsoft.com/\">Malicious link</a>");
        tester.assertTextPresent("Class Settings");
        tester.clickLinkWithText("Classes");

        //Check injection
        tester.assertLinkNotPresentWithText("Malicious link");

    }

    @Test
    public void testVulnerability89() {
        /*Vulnerability 89,ClassSettings.php
         * 
         */
        tester.assertCommentPresent("Not Yet Implemented");

    }

    @Test
    public void testVulnerability92() {
        /*Vulnerability 92,ManageSchoolInfo.php
         * 
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Injection
        tester.clickLinkWithText("School");
        tester.assertMatch("Manage School Information");
        tester.setTextField("schoolname",
                "<a href=\"http://www.microsoft.com\">Malicious link 1</a>"); //max 50 chars
        tester.setTextField("schooladdress",
                "<a href=\"http://www.microsoft.com\">Malicious link 2</a>"); //max 50 chars
        tester.setTextField("schoolphone", "<a href=3.it>3"); //max 14 chars
        tester.setTextField("sitetext",
                "<a href=\"http://www.microsoft.com\">Malicious link 4</a>");
        tester.setTextField("sitemessage",
                "<a href=\"http://www.microsoft.com\">Malicious link 5</a>");
        tester.clickButtonWithText(" Update ");

        //Check injection
        //-----> Go to correct Page!
        tester.assertLinkNotPresentWithText("Malicious link 1");
        tester.assertLinkNotPresentWithText("Malicious link 2");
        tester.assertLinkNotPresentWithText("3");
        tester.clickLinkWithText("Log Out");
        tester.assertLinkNotPresentWithText("Malicious link 4");
        tester.assertLinkNotPresentWithText("Malicious link 5");
    }

    @After
    public void cleanUpVulnerability92() {
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Remove injection
        tester.clickLinkWithText("School");
        tester.assertMatch("Manage School Information");
        tester.setTextField("schoolname", "School Name"); //max 50 chars
        tester.setTextField("schooladdress", "Address"); //max 50 chars
        tester.setTextField("schoolphone", "1234567890"); //max 14 chars
        tester.setTextField("sitetext", "Login Test");
        tester.setTextField("sitemessage", "Today's Message");
        tester.clickButtonWithText(" Update ");
    }

    public void testVulnerability105() {
        /*Login.php line 45, yet done?
         * */
        tester.assertCommentPresent("Not Yet Implemented");
    }

    @Test
    public void testVulnerability111() {
        /* EditTeacher.php
         * <input type='hidden' name='teacherid' value='$id[0]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();

        //Injection
        tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("Teachers");
        tester.assertMatch("Manage Teachers");
        tester.setHiddenField("teacherid", "<a href=\"http://www.microsoft.com/\">Malicious link</a>"); //max 50 chars

        //Check injection
        tester.assertCheckboxPresent("delete[]", "2");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Teachers");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability115() {
        /* EditStudent.php
         * <input type='hidden' name='teacherid' value='$id[0]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();

        //Injection
        tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("Students");
        tester.assertMatch("Manage Students");
        tester.setHiddenField("schoolname", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.assertCheckboxPresent("delete[]", "2");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Students");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability142() {
        /* ParentViewCourses.php
         *  
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "parent");
        tester.setTextField("password", "parent");
        tester.submit();

        //Injection
        tester.assertMatch("Students of Parent Parent");
        tester.clickLinkWithText("Student Student");
        //tester.assertMatch("Manage Students");
        tester.setHiddenField("student", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        //ADD CORRECT PATH
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability146() {
        /* Vulnerability 146,147,148
         * ViewAnnouncements.php
         *  <input type='hidden' name='onpage' value='$_POST[onpage]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher");
        tester.setTextField("password", "teacher");
        tester.submit();

        //Injection
        tester.assertMatch("teacher teacher's Classes");
        tester.clickLinkWithText("Class3");
        tester.clickLinkWithText("Announcements");
        tester.setHiddenField("onpage", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.assertMatch("View Announcements");
        tester.assertLinkNotPresentWithText("Malicious link");

    }

    @Test
    public void testVulnerability149() {
        /* EditUser.php
         * <input type='hidden' name='teacherid' value='$id[0]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();

        //Injection
        tester.assertMatch("Manage Classes");
        tester.clickLinkWithText("Users");
        tester.assertMatch("Manage Users");
        tester.setHiddenField("teacherid", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.assertCheckboxPresent("delete[]", "1");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Users");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability161() {
        /* EditParent.php
         * <input type='hidden' name='teacherid' value='$id[0]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");


        //Injection
        tester.clickLinkWithText("Parents");
        tester.assertMatch("Manage Parents");
        tester.setHiddenField("parentid", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.assertCheckboxPresent("delete[]", "2");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Parents");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability165() {
        /* StudentMain.php
         * <input type='hidden' name='selectclass' value='$_POST[selectclass]' />
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "student");
        tester.setTextField("password", "student");
        tester.submit();
        tester.assertMatch("Student Student's Classes");

        //Injection
        tester.setHiddenField("selectclass", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");
        tester.clickLinkWithText("Classes");
        tester.assertMatch("Student Student's Classes");
        tester.assertLinkNotPresent("Malicious link");
    }

    @Test
    public void testVulnerability180() {
        /* TeachertMain.php
         * <input type='hidden' name='selectclass' value='$_POST[selectclass]' />
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher");
        tester.setTextField("password", "teacher");
        tester.submit();
        tester.assertMatch("teacher teacher's Classes");

        //Injection
        tester.setHiddenField("selectclass", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");
        tester.clickLinkWithText("Classes");
        tester.assertMatch("teacher teacher's Classes");

        tester.assertLinkNotPresent("Malicious link");
    }

    @Test
    public void testVulnerability181() {
        /* ViewStudents.php
         * <input type='hidden' name='selectclass' value='$_POST[selectclass]' />
         */

        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher");
        tester.setTextField("password", "teacher");
        tester.submit();
        tester.assertMatch("teacher teacher's Classes");

        //Injection
        tester.clickLinkWithText("Class3");
        tester.assertMatch("Class Settings");
        tester.setHiddenField("selectclass", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");
        tester.clickLinkWithText("Students");
        tester.assertMatch("Students");

        //Check Injection
        tester.assertLinkNotPresent("Malicious link");
    }

    @Test
    public void testVulnerability183() {
        /* ViewAssignaments.php
         * Vulnerability 183,184
         */

        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "student");
        tester.setTextField("password", "student");
        tester.submit();
        tester.assertMatch("Student Student's Classes");

        //Injection
        tester.clickLinkWithText("Class3");
        tester.assertMatch("Class Settings");
        tester.setHiddenField("selectclass", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");
        tester.clickLinkWithText("Assignments");
        tester.assertMatch("View Assignments");

        //Check Injection
        tester.assertLinkNotPresent("Malicious link");
    }

    @Test
    public void testVulnerability194() {
        /* ParentMain.php
         *    <input type='hidden' name='selectclass' value='$_POST[selectclass]' />
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "parent");
        tester.setTextField("password", "parent");
        tester.submit();
        tester.assertMatch("Students of Parent Parent");

        //Injection
        tester.setHiddenField("selectclass", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");
        tester.clickLinkWithText("Students");
        tester.assertMatch("Students of Parent Parent");
        tester.assertLinkNotPresent("Malicious link");
    }

    @Test
    public void testVulnerability200() {
        /* ViewGrades.php
         * Vulnerability 200, 201
         *  $q = mysql_query("SELECT gradeid, points, submitdate, islate, comment FROM grades WHERE studentid = '$studentid' AND courseid = '$_POST[selectclass]' AND assignmentid = '$assignment[0]'")
         */

        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "student");
        tester.setTextField("password", "student");
        tester.submit();
        tester.assertMatch("Student Student's Classes");

        //Injection
        tester.clickLinkWithText("Class3");
        tester.assertMatch("Class Settings");
        tester.setHiddenField("selectclass", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");
        tester.clickLinkWithText("Grades");
        tester.assertMatch("Grades");

        //Check Injection
        tester.assertLinkNotPresent("Malicious link");
    }

    @Test
    public void testVulnerability239() {
        /* EditClass.php
         * <input type='hidden' name='teacherid' value='$id[0]'>
         * DUPLICATE?
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Injection
        tester.clickLinkWithText("Classes");
        tester.assertMatch("Manage Classes");
        tester.setHiddenField("schoolname", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.assertCheckboxPresent("delete[]", "7");
        tester.clickButtonWithText("Edit");
        tester.assertMatch("Edit Classes");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability257() {
        /*  ManageAssignaments.php
         *  $query = mysql_query("SELECT coursename FROM courses WHERE courseid = '$_POST[selectclass]'") or die("ManageAssignments.php: Unable to get the course name - ".mysql_error());
         *  $coursename = mysql_result($query,0);
         *  print "... $coursename ..."
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher");
        tester.setTextField("password", "teacher");
        tester.submit();
        tester.assertMatch("teacher teacher's Classes");

        //Injection
        tester.clickLinkWithText("Class3");
        tester.assertMatch("Class Settings");
        tester.clickLinkWithExactText("Assignments");
        tester.clickButtonWithText("Add");
        tester.assertMatch("Add New Assignment");
        tester.setTextField("title", "Malicious Task");
        tester.setTextField("task", "Task at this <a href=\"http://www.microsoft.com/\">Malicious link</a>");
        tester.setTextField("total", "10");
        tester.setTextField("assigneddate", "03.03.13");
        tester.setTextField("duedate", "04.04.13");
        tester.clickButtonWithText("Add Assignment");


        //Check injection
        tester.assertMatch("Manage Assignments");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability260() {
        /*  ManageAssignaments.php
         *    <input type='hidden' name='onpage' value='$_POST[onpage]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Injection
        tester.clickLinkWithText("Terms");
        tester.assertMatch("Manage Terms");
        tester.clickButtonWithText("Add");
        tester.assertMatch("Add New Term");
        tester.setTextField("title", "<a href=as.it>T"); //borderline
        tester.setTextField("startdate", "01.06.13");
        tester.setTextField("enddate", "01.12.13");
        tester.clickButtonWithText("Add Term");


        //Check injection
        tester.assertMatch("Manage Terms");
        tester.assertLinkNotPresentWithText("T");
    }

    @After
    public void cleanUpVulnerability260() {
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Injection
        tester.clickLinkWithText("Terms");
        tester.assertMatch("Manage Terms");
        tester.clickButtonWithText("Add");
        tester.assertMatch("Add New Term");
        tester.setTextField("title", "Term1"); //borderline
        tester.setTextField("startdate", "01.06.13");
        tester.setTextField("enddate", "01.12.13");
        tester.clickButtonWithText("Add Term");
    }

    @Test
    public void testVulnerability268() {
        /*ManageSemester.php
         * Vulnerability 269, 273
         *  <input type='hidden' name='onpage' value='$_POST[onpage]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Injection
        tester.clickLinkWithText("Semesters");
        tester.assertMatch("Manage Semesters");
        tester.setHiddenField("onpage", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.clickLinkWithText("Semesters");
        tester.assertMatch("Manage Semesters");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability269() {
        /* AddClass.php
         * <input type='hidden' name='fullyear' value='$_POST[fullyear]' />
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Check Injection
        tester.clickButtonWithText("Add");
        tester.assertMatch("Add New Class");
        tester.setHiddenField("fullyear", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.clickButtonWithText("Full Year");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability283() {
        /* ManageUsers.php

         * <input type='hidden' name='onpage' value='$_POST[onpage]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Injection
        tester.clickLinkWithText("Users");
        tester.assertMatch("Manage Users");
        tester.setHiddenField("onpage", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.clickLinkWithText("Users");
        tester.assertMatch("Manage Users");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability288() {
        /* ManageParents.php
         * <input type='hidden' name='onpage' value='$_POST[onpage]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Injection
        tester.clickLinkWithText("Parents");
        tester.assertMatch("Manage Parents");
        tester.setHiddenField("onpage", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.clickLinkWithText("Parents");
        tester.assertMatch("Manage Parents");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    @Test
    public void testVulnerability293() {
        /* ManageStudents.php
         * <input type='hidden' name='onpage' value='$_POST[onpage]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Classes");

        //Injection
        tester.clickLinkWithText("Students");
        tester.assertMatch("Manage Students");
        tester.setHiddenField("onpage", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.clickLinkWithText("Students");
        tester.assertMatch("Manage Students");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    public void testVulnerability309() {
        /* ManageAssignaments.php
         * <input type='hidden' name='selectclass' value='$_POST[selectclass]' />
         * <input type='hidden' name='onpage' value='$_POST[onpage]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher");
        tester.setTextField("password", "teacher");
        tester.submit();
        tester.assertMatch("teacher teacher's Classes");

        //First Injection
        tester.clickLinkWithText("Class3");
        tester.assertMatch("Class Settings");
        tester.clickLinkWithText("Assignments");
        tester.assertMatch("Manage Assignments");
        tester.setHiddenField("selectclass", "<a href=\"http://www.microsoft.com/\">Malicious link selectclass</a>");
        //Second Injection
        tester.setHiddenField("onpage", "<a href=\"http://www.microsoft.com/\">Malicious link onpage</a>");

        //Check First Injection
        tester.clickLinkWithText("Assignments");
        tester.assertMatch("Manage Assignments");
        tester.assertLinkNotPresentWithText("Malicious link selectclass");
        //Check Second Injection
        tester.assertLinkNotPresentWithText("Malicious link onpage");

    }

    public void testVulnerability316() {
        /* ManageStudents.php
         *   <input type='hidden' name='selectclass' value='$_POST[selectclass]' />
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "teacher");
        tester.setTextField("password", "teacher");
        tester.submit();
        tester.assertMatch("Manage Semester");

        //Injection
        tester.clickLinkWithText("Class3");
        tester.assertMatch("Class Settings");
        tester.clickLinkWithText("Grades");
        tester.assertMatch("Grades");
        tester.setHiddenField("selectclass", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.clickLinkWithText("Grades");
        tester.assertMatch("Grades");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    public void testVulnerability320() {
        /* ManageStudents.php
         * <input type='hidden' name='onpage' value='$_POST[onpage]'>
         */
        tester.beginAt("index.php");
        tester.assertMatch("Today's Message");

        tester.setTextField("username", "admin");
        tester.setTextField("password", "admin");
        tester.submit();
        tester.assertMatch("Manage Semester");

        //Injection
        tester.clickLinkWithText("Classes");
        tester.assertMatch("Manage Classes");
        tester.setHiddenField("onpage", "<a href=\"http://www.microsoft.com/\">Malicious link</a>");

        //Check injection
        tester.clickLinkWithText("Classes");
        tester.assertMatch("Manage Classes");
        tester.assertLinkNotPresentWithText("Malicious link");
    }

    //Mariano Ceccato:
    @After
    public void cleanUp() {

        if (previousValue != null) {
            tester.beginAt("index.php");

            tester.setTextField("username", "schoolmate");
            tester.setTextField("password", "schoolmate");
            tester.submit();

            tester.clickLinkWithText("School");

            tester.assertMatch("Manage School Information");
            tester.setTextField("sitetext", previousValue);
            tester.clickButtonWithText(" Update ");

            tester.clickLinkWithText("Log Out");
        }

    }
}