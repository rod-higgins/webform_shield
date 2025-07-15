<?php

namespace Drupal\Tests\webform_shield\FunctionalJavascript;

use Drupal\FunctionalJavascriptTests\WebDriverTestBase;

/**
 * Tests Webform Shield with JavaScript enabled.
 *
 * @group webform_shield
 */
class WebformShieldJavaScriptTest extends WebDriverTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['webform_shield'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests that forms work after human interaction.
   */
  public function testHumanInteraction() {
    $this->drupalGet('/user/password');
    $page = $this->getSession()->getPage();
    $driver = $this->getSession()->getDriver();

    // Fill the name field.
    $name = $this->randomMachineName();
    $page->fillField('Username or email address', $name);

    // Simulate human behavior by moving mouse.
    $driver->mouseOver('//h1[text() = "Reset your password"]');
    
    // Submit the form.
    $page->pressButton('Submit');

    // Should NOT be on the blocked page - should process the form normally.
    $this->assertSession()->addressNotEquals('/webform-shield');
    
    // Should see the normal form validation message.
    $this->assertSession()->waitForText("{$name} is not recognized as a username or an email address.");
  }

}